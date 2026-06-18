/** Auto-generated */
package me.bechberger.ebpf.runtime;

import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.InlineUnion;
import me.bechberger.ebpf.annotations.Offset;
import me.bechberger.ebpf.annotations.OriginalName;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.ebpf.type.Struct;
import me.bechberger.ebpf.type.TypedEnum;
import me.bechberger.ebpf.type.TypedefBase;
import me.bechberger.ebpf.type.Union;
import org.jetbrains.annotations.Nullable;
import static me.bechberger.ebpf.runtime.AaDefinitions.*;
import static me.bechberger.ebpf.runtime.AafsDefinitions.*;
import static me.bechberger.ebpf.runtime.Aat2870Definitions.*;
import static me.bechberger.ebpf.runtime.AccountDefinitions.*;
import static me.bechberger.ebpf.runtime.AcctDefinitions.*;
import static me.bechberger.ebpf.runtime.AcompDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiphpDefinitions.*;
import static me.bechberger.ebpf.runtime.ActionDefinitions.*;
import static me.bechberger.ebpf.runtime.ActiveDefinitions.*;
import static me.bechberger.ebpf.runtime.AddDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrconfDefinitions.*;
import static me.bechberger.ebpf.runtime.AdjustDefinitions.*;
import static me.bechberger.ebpf.runtime.AdlDefinitions.*;
import static me.bechberger.ebpf.runtime.Adp5520Definitions.*;
import static me.bechberger.ebpf.runtime.AdvisorDefinitions.*;
import static me.bechberger.ebpf.runtime.AeadDefinitions.*;
import static me.bechberger.ebpf.runtime.AerDefinitions.*;
import static me.bechberger.ebpf.runtime.AgpDefinitions.*;
import static me.bechberger.ebpf.runtime.AhashDefinitions.*;
import static me.bechberger.ebpf.runtime.AioDefinitions.*;
import static me.bechberger.ebpf.runtime.AlarmDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocateDefinitions.*;
import static me.bechberger.ebpf.runtime.AmdDefinitions.*;
import static me.bechberger.ebpf.runtime.AmlDefinitions.*;
import static me.bechberger.ebpf.runtime.AnonDefinitions.*;
import static me.bechberger.ebpf.runtime.ApeiDefinitions.*;
import static me.bechberger.ebpf.runtime.ApicDefinitions.*;
import static me.bechberger.ebpf.runtime.ApparmorDefinitions.*;
import static me.bechberger.ebpf.runtime.AppendDefinitions.*;
import static me.bechberger.ebpf.runtime.ApplyDefinitions.*;
import static me.bechberger.ebpf.runtime.ArchDefinitions.*;
import static me.bechberger.ebpf.runtime.ArenaDefinitions.*;
import static me.bechberger.ebpf.runtime.ArpDefinitions.*;
import static me.bechberger.ebpf.runtime.ArrayDefinitions.*;
import static me.bechberger.ebpf.runtime.Asn1Definitions.*;
import static me.bechberger.ebpf.runtime.AssocDefinitions.*;
import static me.bechberger.ebpf.runtime.AsymmetricDefinitions.*;
import static me.bechberger.ebpf.runtime.AsyncDefinitions.*;
import static me.bechberger.ebpf.runtime.AtaDefinitions.*;
import static me.bechberger.ebpf.runtime.AtkbdDefinitions.*;
import static me.bechberger.ebpf.runtime.AtomicDefinitions.*;
import static me.bechberger.ebpf.runtime.AttachDefinitions.*;
import static me.bechberger.ebpf.runtime.AttributeDefinitions.*;
import static me.bechberger.ebpf.runtime.AuditDefinitions.*;
import static me.bechberger.ebpf.runtime.AuxiliaryDefinitions.*;
import static me.bechberger.ebpf.runtime.AvailableDefinitions.*;
import static me.bechberger.ebpf.runtime.AvcDefinitions.*;
import static me.bechberger.ebpf.runtime.AvtabDefinitions.*;
import static me.bechberger.ebpf.runtime.BackingDefinitions.*;
import static me.bechberger.ebpf.runtime.BacklightDefinitions.*;
import static me.bechberger.ebpf.runtime.BadDefinitions.*;
import static me.bechberger.ebpf.runtime.BadblocksDefinitions.*;
import static me.bechberger.ebpf.runtime.BalanceDefinitions.*;
import static me.bechberger.ebpf.runtime.BalloonDefinitions.*;
import static me.bechberger.ebpf.runtime.BdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BdiDefinitions.*;
import static me.bechberger.ebpf.runtime.BgpioDefinitions.*;
import static me.bechberger.ebpf.runtime.BhDefinitions.*;
import static me.bechberger.ebpf.runtime.BindDefinitions.*;
import static me.bechberger.ebpf.runtime.BioDefinitions.*;
import static me.bechberger.ebpf.runtime.BitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.Blake2sDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkcgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkifDefinitions.*;
import static me.bechberger.ebpf.runtime.BlockDefinitions.*;
import static me.bechberger.ebpf.runtime.BloomDefinitions.*;
import static me.bechberger.ebpf.runtime.BootDefinitions.*;
import static me.bechberger.ebpf.runtime.BpfDefinitions.*;
import static me.bechberger.ebpf.runtime.BqlDefinitions.*;
import static me.bechberger.ebpf.runtime.BsgDefinitions.*;
import static me.bechberger.ebpf.runtime.BtfDefinitions.*;
import static me.bechberger.ebpf.runtime.BtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.BtsDefinitions.*;
import static me.bechberger.ebpf.runtime.BufferDefinitions.*;
import static me.bechberger.ebpf.runtime.BuildDefinitions.*;
import static me.bechberger.ebpf.runtime.BusDefinitions.*;
import static me.bechberger.ebpf.runtime.BytDefinitions.*;
import static me.bechberger.ebpf.runtime.CacheDefinitions.*;
import static me.bechberger.ebpf.runtime.CalcDefinitions.*;
import static me.bechberger.ebpf.runtime.CalculateDefinitions.*;
import static me.bechberger.ebpf.runtime.CalipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.CallDefinitions.*;
import static me.bechberger.ebpf.runtime.CanDefinitions.*;
import static me.bechberger.ebpf.runtime.CapDefinitions.*;
import static me.bechberger.ebpf.runtime.CcDefinitions.*;
import static me.bechberger.ebpf.runtime.CdevDefinitions.*;
import static me.bechberger.ebpf.runtime.CdromDefinitions.*;
import static me.bechberger.ebpf.runtime.CeaDefinitions.*;
import static me.bechberger.ebpf.runtime.Cfg80211Definitions.*;
import static me.bechberger.ebpf.runtime.Cgroup1Definitions.*;
import static me.bechberger.ebpf.runtime.CgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ChangeDefinitions.*;
import static me.bechberger.ebpf.runtime.ChargerDefinitions.*;
import static me.bechberger.ebpf.runtime.CheckDefinitions.*;
import static me.bechberger.ebpf.runtime.ChvDefinitions.*;
import static me.bechberger.ebpf.runtime.CipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.ClassDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanupDefinitions.*;
import static me.bechberger.ebpf.runtime.ClearDefinitions.*;
import static me.bechberger.ebpf.runtime.ClkDefinitions.*;
import static me.bechberger.ebpf.runtime.ClockeventsDefinitions.*;
import static me.bechberger.ebpf.runtime.ClocksourceDefinitions.*;
import static me.bechberger.ebpf.runtime.ClosureDefinitions.*;
import static me.bechberger.ebpf.runtime.CmaDefinitions.*;
import static me.bechberger.ebpf.runtime.CmciDefinitions.*;
import static me.bechberger.ebpf.runtime.CmdlineDefinitions.*;
import static me.bechberger.ebpf.runtime.CmisDefinitions.*;
import static me.bechberger.ebpf.runtime.CmosDefinitions.*;
import static me.bechberger.ebpf.runtime.CmpDefinitions.*;
import static me.bechberger.ebpf.runtime.CnDefinitions.*;
import static me.bechberger.ebpf.runtime.CollapseDefinitions.*;
import static me.bechberger.ebpf.runtime.CollectDefinitions.*;
import static me.bechberger.ebpf.runtime.CommonDefinitions.*;
import static me.bechberger.ebpf.runtime.CompactionDefinitions.*;
import static me.bechberger.ebpf.runtime.CompatDefinitions.*;
import static me.bechberger.ebpf.runtime.ComponentDefinitions.*;
import static me.bechberger.ebpf.runtime.ComputeDefinitions.*;
import static me.bechberger.ebpf.runtime.ConDefinitions.*;
import static me.bechberger.ebpf.runtime.CondDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigfsDefinitions.*;
import static me.bechberger.ebpf.runtime.ConsoleDefinitions.*;
import static me.bechberger.ebpf.runtime.ContextDefinitions.*;
import static me.bechberger.ebpf.runtime.ConvertDefinitions.*;
import static me.bechberger.ebpf.runtime.CookieDefinitions.*;
import static me.bechberger.ebpf.runtime.CopyDefinitions.*;
import static me.bechberger.ebpf.runtime.CoreDefinitions.*;
import static me.bechberger.ebpf.runtime.CoredumpDefinitions.*;
import static me.bechberger.ebpf.runtime.CountDefinitions.*;
import static me.bechberger.ebpf.runtime.CpciDefinitions.*;
import static me.bechberger.ebpf.runtime.CperDefinitions.*;
import static me.bechberger.ebpf.runtime.CppcDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuacctDefinitions.*;
import static me.bechberger.ebpf.runtime.CpufreqDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuhpDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuidleDefinitions.*;
import static me.bechberger.ebpf.runtime.CpumaskDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusetDefinitions.*;
import static me.bechberger.ebpf.runtime.CrashDefinitions.*;
import static me.bechberger.ebpf.runtime.CrbDefinitions.*;
import static me.bechberger.ebpf.runtime.Crc64Definitions.*;
import static me.bechberger.ebpf.runtime.CreateDefinitions.*;
import static me.bechberger.ebpf.runtime.CryptoDefinitions.*;
import static me.bechberger.ebpf.runtime.CrystalcoveDefinitions.*;
import static me.bechberger.ebpf.runtime.CssDefinitions.*;
import static me.bechberger.ebpf.runtime.CsumDefinitions.*;
import static me.bechberger.ebpf.runtime.CtDefinitions.*;
import static me.bechberger.ebpf.runtime.CtrlDefinitions.*;
import static me.bechberger.ebpf.runtime.CtxDefinitions.*;
import static me.bechberger.ebpf.runtime.CurrentDefinitions.*;
import static me.bechberger.ebpf.runtime.CxlDefinitions.*;
import static me.bechberger.ebpf.runtime.DDefinitions.*;
import static me.bechberger.ebpf.runtime.Da903xDefinitions.*;
import static me.bechberger.ebpf.runtime.Da9052Definitions.*;
import static me.bechberger.ebpf.runtime.Da9063Definitions.*;
import static me.bechberger.ebpf.runtime.DataDefinitions.*;
import static me.bechberger.ebpf.runtime.DaxDefinitions.*;
import static me.bechberger.ebpf.runtime.DbcDefinitions.*;
import static me.bechberger.ebpf.runtime.DbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbnlDefinitions.*;
import static me.bechberger.ebpf.runtime.DdDefinitions.*;
import static me.bechberger.ebpf.runtime.DdebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DeadlineDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugfsDefinitions.*;
import static me.bechberger.ebpf.runtime.DecDefinitions.*;
import static me.bechberger.ebpf.runtime.DefaultDefinitions.*;
import static me.bechberger.ebpf.runtime.DeferredDefinitions.*;
import static me.bechberger.ebpf.runtime.DeflateDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayacctDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayedDefinitions.*;
import static me.bechberger.ebpf.runtime.DeleteDefinitions.*;
import static me.bechberger.ebpf.runtime.DentryDefinitions.*;
import static me.bechberger.ebpf.runtime.DequeueDefinitions.*;
import static me.bechberger.ebpf.runtime.DescDefinitions.*;
import static me.bechberger.ebpf.runtime.DestroyDefinitions.*;
import static me.bechberger.ebpf.runtime.DetachDefinitions.*;
import static me.bechberger.ebpf.runtime.DevDefinitions.*;
import static me.bechberger.ebpf.runtime.DevcdDefinitions.*;
import static me.bechberger.ebpf.runtime.DevfreqDefinitions.*;
import static me.bechberger.ebpf.runtime.DeviceDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.DevmDefinitions.*;
import static me.bechberger.ebpf.runtime.DevptsDefinitions.*;
import static me.bechberger.ebpf.runtime.DevresDefinitions.*;
import static me.bechberger.ebpf.runtime.DhDefinitions.*;
import static me.bechberger.ebpf.runtime.DimDefinitions.*;
import static me.bechberger.ebpf.runtime.DisableDefinitions.*;
import static me.bechberger.ebpf.runtime.DiskDefinitions.*;
import static me.bechberger.ebpf.runtime.DispatchDefinitions.*;
import static me.bechberger.ebpf.runtime.DisplayidDefinitions.*;
import static me.bechberger.ebpf.runtime.DlDefinitions.*;
import static me.bechberger.ebpf.runtime.DmDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaDefinitions.*;
import static me.bechberger.ebpf.runtime.DmabufDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaengineDefinitions.*;
import static me.bechberger.ebpf.runtime.DmarDefinitions.*;
import static me.bechberger.ebpf.runtime.DmemDefinitions.*;
import static me.bechberger.ebpf.runtime.DmiDefinitions.*;
import static me.bechberger.ebpf.runtime.DnsDefinitions.*;
import static me.bechberger.ebpf.runtime.DoDefinitions.*;
import static me.bechberger.ebpf.runtime.DomainDefinitions.*;
import static me.bechberger.ebpf.runtime.DownDefinitions.*;
import static me.bechberger.ebpf.runtime.DpcDefinitions.*;
import static me.bechberger.ebpf.runtime.DpllDefinitions.*;
import static me.bechberger.ebpf.runtime.DpmDefinitions.*;
import static me.bechberger.ebpf.runtime.DquotDefinitions.*;
import static me.bechberger.ebpf.runtime.DrainDefinitions.*;
import static me.bechberger.ebpf.runtime.DrbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DriverDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmmDefinitions.*;
import static me.bechberger.ebpf.runtime.DropDefinitions.*;
import static me.bechberger.ebpf.runtime.DsaDefinitions.*;
import static me.bechberger.ebpf.runtime.DstDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyconDefinitions.*;
import static me.bechberger.ebpf.runtime.DumpDefinitions.*;
import static me.bechberger.ebpf.runtime.DupDefinitions.*;
import static me.bechberger.ebpf.runtime.DvdDefinitions.*;
import static me.bechberger.ebpf.runtime.DwDefinitions.*;
import static me.bechberger.ebpf.runtime.Dwc2Definitions.*;
import static me.bechberger.ebpf.runtime.DxDefinitions.*;
import static me.bechberger.ebpf.runtime.DynDefinitions.*;
import static me.bechberger.ebpf.runtime.DyneventDefinitions.*;
import static me.bechberger.ebpf.runtime.EafnosupportDefinitions.*;
import static me.bechberger.ebpf.runtime.EarlyDefinitions.*;
import static me.bechberger.ebpf.runtime.EbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.EcDefinitions.*;
import static me.bechberger.ebpf.runtime.EccDefinitions.*;
import static me.bechberger.ebpf.runtime.EcryptfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EdacDefinitions.*;
import static me.bechberger.ebpf.runtime.EddDefinitions.*;
import static me.bechberger.ebpf.runtime.EdidDefinitions.*;
import static me.bechberger.ebpf.runtime.EfiDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EhciDefinitions.*;
import static me.bechberger.ebpf.runtime.ElantsDefinitions.*;
import static me.bechberger.ebpf.runtime.ElevatorDefinitions.*;
import static me.bechberger.ebpf.runtime.ElfDefinitions.*;
import static me.bechberger.ebpf.runtime.ElvDefinitions.*;
import static me.bechberger.ebpf.runtime.EmDefinitions.*;
import static me.bechberger.ebpf.runtime.EmitDefinitions.*;
import static me.bechberger.ebpf.runtime.EnableDefinitions.*;
import static me.bechberger.ebpf.runtime.EndDefinitions.*;
import static me.bechberger.ebpf.runtime.EnqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.EpDefinitions.*;
import static me.bechberger.ebpf.runtime.EprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.ErstDefinitions.*;
import static me.bechberger.ebpf.runtime.EspintcpDefinitions.*;
import static me.bechberger.ebpf.runtime.EthDefinitions.*;
import static me.bechberger.ebpf.runtime.EthnlDefinitions.*;
import static me.bechberger.ebpf.runtime.EthtoolDefinitions.*;
import static me.bechberger.ebpf.runtime.EvdevDefinitions.*;
import static me.bechberger.ebpf.runtime.EventDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfdDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EvmDefinitions.*;
import static me.bechberger.ebpf.runtime.EvtchnDefinitions.*;
import static me.bechberger.ebpf.runtime.ExcDefinitions.*;
import static me.bechberger.ebpf.runtime.ExecmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ExitDefinitions.*;
import static me.bechberger.ebpf.runtime.Ext4Definitions.*;
import static me.bechberger.ebpf.runtime.ExtconDefinitions.*;
import static me.bechberger.ebpf.runtime.FDefinitions.*;
import static me.bechberger.ebpf.runtime.FanotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FatDefinitions.*;
import static me.bechberger.ebpf.runtime.FaultDefinitions.*;
import static me.bechberger.ebpf.runtime.FauxDefinitions.*;
import static me.bechberger.ebpf.runtime.FbDefinitions.*;
import static me.bechberger.ebpf.runtime.FbconDefinitions.*;
import static me.bechberger.ebpf.runtime.FdtDefinitions.*;
import static me.bechberger.ebpf.runtime.FfDefinitions.*;
import static me.bechberger.ebpf.runtime.FgraphDefinitions.*;
import static me.bechberger.ebpf.runtime.Fib4Definitions.*;
import static me.bechberger.ebpf.runtime.Fib6Definitions.*;
import static me.bechberger.ebpf.runtime.FibDefinitions.*;
import static me.bechberger.ebpf.runtime.FifoDefinitions.*;
import static me.bechberger.ebpf.runtime.FileDefinitions.*;
import static me.bechberger.ebpf.runtime.FilemapDefinitions.*;
import static me.bechberger.ebpf.runtime.FilenameDefinitions.*;
import static me.bechberger.ebpf.runtime.FillDefinitions.*;
import static me.bechberger.ebpf.runtime.FilterDefinitions.*;
import static me.bechberger.ebpf.runtime.FindDefinitions.*;
import static me.bechberger.ebpf.runtime.FinishDefinitions.*;
import static me.bechberger.ebpf.runtime.FirmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.FixedDefinitions.*;
import static me.bechberger.ebpf.runtime.FixupDefinitions.*;
import static me.bechberger.ebpf.runtime.FlowDefinitions.*;
import static me.bechberger.ebpf.runtime.FlushDefinitions.*;
import static me.bechberger.ebpf.runtime.FnDefinitions.*;
import static me.bechberger.ebpf.runtime.FolioDefinitions.*;
import static me.bechberger.ebpf.runtime.FollowDefinitions.*;
import static me.bechberger.ebpf.runtime.FopsDefinitions.*;
import static me.bechberger.ebpf.runtime.ForDefinitions.*;
import static me.bechberger.ebpf.runtime.ForceDefinitions.*;
import static me.bechberger.ebpf.runtime.FprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.FpuDefinitions.*;
import static me.bechberger.ebpf.runtime.FredDefinitions.*;
import static me.bechberger.ebpf.runtime.FreeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezerDefinitions.*;
import static me.bechberger.ebpf.runtime.FreqDefinitions.*;
import static me.bechberger.ebpf.runtime.FromDefinitions.*;
import static me.bechberger.ebpf.runtime.FsDefinitions.*;
import static me.bechberger.ebpf.runtime.FscryptDefinitions.*;
import static me.bechberger.ebpf.runtime.FseDefinitions.*;
import static me.bechberger.ebpf.runtime.FsnotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FsverityDefinitions.*;
import static me.bechberger.ebpf.runtime.FtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.FullDefinitions.*;
import static me.bechberger.ebpf.runtime.FunctionDefinitions.*;
import static me.bechberger.ebpf.runtime.FuseDefinitions.*;
import static me.bechberger.ebpf.runtime.FutexDefinitions.*;
import static me.bechberger.ebpf.runtime.FwDefinitions.*;
import static me.bechberger.ebpf.runtime.FwnodeDefinitions.*;
import static me.bechberger.ebpf.runtime.GartDefinitions.*;
import static me.bechberger.ebpf.runtime.GcmDefinitions.*;
import static me.bechberger.ebpf.runtime.GenDefinitions.*;
import static me.bechberger.ebpf.runtime.GenericDefinitions.*;
import static me.bechberger.ebpf.runtime.GenlDefinitions.*;
import static me.bechberger.ebpf.runtime.GenpdDefinitions.*;
import static me.bechberger.ebpf.runtime.GenphyDefinitions.*;
import static me.bechberger.ebpf.runtime.GetDefinitions.*;
import static me.bechberger.ebpf.runtime.GhesDefinitions.*;
import static me.bechberger.ebpf.runtime.GnetDefinitions.*;
import static me.bechberger.ebpf.runtime.GnttabDefinitions.*;
import static me.bechberger.ebpf.runtime.GpioDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiochipDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiodDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiolibDefinitions.*;
import static me.bechberger.ebpf.runtime.GroDefinitions.*;
import static me.bechberger.ebpf.runtime.GroupDefinitions.*;
import static me.bechberger.ebpf.runtime.GupDefinitions.*;
import static me.bechberger.ebpf.runtime.HandleDefinitions.*;
import static me.bechberger.ebpf.runtime.HandshakeDefinitions.*;
import static me.bechberger.ebpf.runtime.HasDefinitions.*;
import static me.bechberger.ebpf.runtime.HashDefinitions.*;
import static me.bechberger.ebpf.runtime.HcdDefinitions.*;
import static me.bechberger.ebpf.runtime.HctxDefinitions.*;
import static me.bechberger.ebpf.runtime.HdmiDefinitions.*;
import static me.bechberger.ebpf.runtime.HfiDefinitions.*;
import static me.bechberger.ebpf.runtime.HidDefinitions.*;
import static me.bechberger.ebpf.runtime.HistDefinitions.*;
import static me.bechberger.ebpf.runtime.HmacDefinitions.*;
import static me.bechberger.ebpf.runtime.HmatDefinitions.*;
import static me.bechberger.ebpf.runtime.HmmDefinitions.*;
import static me.bechberger.ebpf.runtime.HookDefinitions.*;
import static me.bechberger.ebpf.runtime.HpetDefinitions.*;
import static me.bechberger.ebpf.runtime.HrtimerDefinitions.*;
import static me.bechberger.ebpf.runtime.HsuDefinitions.*;
import static me.bechberger.ebpf.runtime.HswepDefinitions.*;
import static me.bechberger.ebpf.runtime.HtabDefinitions.*;
import static me.bechberger.ebpf.runtime.HteDefinitions.*;
import static me.bechberger.ebpf.runtime.HubDefinitions.*;
import static me.bechberger.ebpf.runtime.HufDefinitions.*;
import static me.bechberger.ebpf.runtime.HugepageDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbfsDefinitions.*;
import static me.bechberger.ebpf.runtime.HvDefinitions.*;
import static me.bechberger.ebpf.runtime.HvcDefinitions.*;
import static me.bechberger.ebpf.runtime.HwDefinitions.*;
import static me.bechberger.ebpf.runtime.HwlatDefinitions.*;
import static me.bechberger.ebpf.runtime.HwmonDefinitions.*;
import static me.bechberger.ebpf.runtime.HybridDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervisorDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cdevDefinitions.*;
import static me.bechberger.ebpf.runtime.I8042Definitions.*;
import static me.bechberger.ebpf.runtime.Ia32Definitions.*;
import static me.bechberger.ebpf.runtime.IbDefinitions.*;
import static me.bechberger.ebpf.runtime.IccDefinitions.*;
import static me.bechberger.ebpf.runtime.IcmpDefinitions.*;
import static me.bechberger.ebpf.runtime.Icmpv6Definitions.*;
import static me.bechberger.ebpf.runtime.IcxDefinitions.*;
import static me.bechberger.ebpf.runtime.IdleDefinitions.*;
import static me.bechberger.ebpf.runtime.IdrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ieee80211Definitions.*;
import static me.bechberger.ebpf.runtime.IflaDefinitions.*;
import static me.bechberger.ebpf.runtime.Igmp6Definitions.*;
import static me.bechberger.ebpf.runtime.IgmpDefinitions.*;
import static me.bechberger.ebpf.runtime.ImaDefinitions.*;
import static me.bechberger.ebpf.runtime.ImsttfbDefinitions.*;
import static me.bechberger.ebpf.runtime.In6Definitions.*;
import static me.bechberger.ebpf.runtime.InDefinitions.*;
import static me.bechberger.ebpf.runtime.IncDefinitions.*;
import static me.bechberger.ebpf.runtime.Inet6Definitions.*;
import static me.bechberger.ebpf.runtime.InetDefinitions.*;
import static me.bechberger.ebpf.runtime.InitDefinitions.*;
import static me.bechberger.ebpf.runtime.InodeDefinitions.*;
import static me.bechberger.ebpf.runtime.InotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.InputDefinitions.*;
import static me.bechberger.ebpf.runtime.InsertDefinitions.*;
import static me.bechberger.ebpf.runtime.InsnDefinitions.*;
import static me.bechberger.ebpf.runtime.IntDefinitions.*;
import static me.bechberger.ebpf.runtime.IntegrityDefinitions.*;
import static me.bechberger.ebpf.runtime.IntelDefinitions.*;
import static me.bechberger.ebpf.runtime.IntervalDefinitions.*;
import static me.bechberger.ebpf.runtime.InvalidateDefinitions.*;
import static me.bechberger.ebpf.runtime.IoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ioam6Definitions.*;
import static me.bechberger.ebpf.runtime.IoapicDefinitions.*;
import static me.bechberger.ebpf.runtime.IocDefinitions.*;
import static me.bechberger.ebpf.runtime.IocgDefinitions.*;
import static me.bechberger.ebpf.runtime.IoctlDefinitions.*;
import static me.bechberger.ebpf.runtime.IomapDefinitions.*;
import static me.bechberger.ebpf.runtime.IommuDefinitions.*;
import static me.bechberger.ebpf.runtime.IommufdDefinitions.*;
import static me.bechberger.ebpf.runtime.IopfDefinitions.*;
import static me.bechberger.ebpf.runtime.IoremapDefinitions.*;
import static me.bechberger.ebpf.runtime.IosfDefinitions.*;
import static me.bechberger.ebpf.runtime.IovDefinitions.*;
import static me.bechberger.ebpf.runtime.IovaDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip4Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6addrlblDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip6mrDefinitions.*;
import static me.bechberger.ebpf.runtime.IpDefinitions.*;
import static me.bechberger.ebpf.runtime.IpcDefinitions.*;
import static me.bechberger.ebpf.runtime.IpeDefinitions.*;
import static me.bechberger.ebpf.runtime.IpmrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ipv4Definitions.*;
import static me.bechberger.ebpf.runtime.Ipv6Definitions.*;
import static me.bechberger.ebpf.runtime.IrqDefinitions.*;
import static me.bechberger.ebpf.runtime.IrteDefinitions.*;
import static me.bechberger.ebpf.runtime.IsDefinitions.*;
import static me.bechberger.ebpf.runtime.IsaDefinitions.*;
import static me.bechberger.ebpf.runtime.IsolateDefinitions.*;
import static me.bechberger.ebpf.runtime.IterDefinitions.*;
import static me.bechberger.ebpf.runtime.IvbepDefinitions.*;
import static me.bechberger.ebpf.runtime.IwDefinitions.*;
import static me.bechberger.ebpf.runtime.JailhouseDefinitions.*;
import static me.bechberger.ebpf.runtime.Jbd2Definitions.*;
import static me.bechberger.ebpf.runtime.JentDefinitions.*;
import static me.bechberger.ebpf.runtime.JournalDefinitions.*;
import static me.bechberger.ebpf.runtime.JumpDefinitions.*;
import static me.bechberger.ebpf.runtime.KDefinitions.*;
import static me.bechberger.ebpf.runtime.KallsymsDefinitions.*;
import static me.bechberger.ebpf.runtime.KbdDefinitions.*;
import static me.bechberger.ebpf.runtime.KdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KernDefinitions.*;
import static me.bechberger.ebpf.runtime.KernelDefinitions.*;
import static me.bechberger.ebpf.runtime.KernfsDefinitions.*;
import static me.bechberger.ebpf.runtime.KexecDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyctlDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyringDefinitions.*;
import static me.bechberger.ebpf.runtime.KfenceDefinitions.*;
import static me.bechberger.ebpf.runtime.KfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.KfreeDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbocDefinitions.*;
import static me.bechberger.ebpf.runtime.KhoDefinitions.*;
import static me.bechberger.ebpf.runtime.KillDefinitions.*;
import static me.bechberger.ebpf.runtime.KimageDefinitions.*;
import static me.bechberger.ebpf.runtime.KlistDefinitions.*;
import static me.bechberger.ebpf.runtime.KlpDefinitions.*;
import static me.bechberger.ebpf.runtime.KmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.KmemDefinitions.*;
import static me.bechberger.ebpf.runtime.KmsgDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjectDefinitions.*;
import static me.bechberger.ebpf.runtime.KprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.KsmDefinitions.*;
import static me.bechberger.ebpf.runtime.KsysDefinitions.*;
import static me.bechberger.ebpf.runtime.KthreadDefinitions.*;
import static me.bechberger.ebpf.runtime.KtimeDefinitions.*;
import static me.bechberger.ebpf.runtime.KvmDefinitions.*;
import static me.bechberger.ebpf.runtime.L3mdevDefinitions.*;
import static me.bechberger.ebpf.runtime.LabelDefinitions.*;
import static me.bechberger.ebpf.runtime.LandlockDefinitions.*;
import static me.bechberger.ebpf.runtime.LapicDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.LedDefinitions.*;
import static me.bechberger.ebpf.runtime.LedtrigDefinitions.*;
import static me.bechberger.ebpf.runtime.LegacyDefinitions.*;
import static me.bechberger.ebpf.runtime.LinearDefinitions.*;
import static me.bechberger.ebpf.runtime.LineeventDefinitions.*;
import static me.bechberger.ebpf.runtime.LinereqDefinitions.*;
import static me.bechberger.ebpf.runtime.LinkDefinitions.*;
import static me.bechberger.ebpf.runtime.LinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.ListDefinitions.*;
import static me.bechberger.ebpf.runtime.LoadDefinitions.*;
import static me.bechberger.ebpf.runtime.LocalDefinitions.*;
import static me.bechberger.ebpf.runtime.LockDefinitions.*;
import static me.bechberger.ebpf.runtime.LocksDefinitions.*;
import static me.bechberger.ebpf.runtime.LockupDefinitions.*;
import static me.bechberger.ebpf.runtime.LogDefinitions.*;
import static me.bechberger.ebpf.runtime.LookupDefinitions.*;
import static me.bechberger.ebpf.runtime.LoopDefinitions.*;
import static me.bechberger.ebpf.runtime.Lp8788Definitions.*;
import static me.bechberger.ebpf.runtime.LpssDefinitions.*;
import static me.bechberger.ebpf.runtime.LruDefinitions.*;
import static me.bechberger.ebpf.runtime.LskcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.LsmDefinitions.*;
import static me.bechberger.ebpf.runtime.LwtunnelDefinitions.*;
import static me.bechberger.ebpf.runtime.Lz4Definitions.*;
import static me.bechberger.ebpf.runtime.MachineDefinitions.*;
import static me.bechberger.ebpf.runtime.MacsecDefinitions.*;
import static me.bechberger.ebpf.runtime.MadviseDefinitions.*;
import static me.bechberger.ebpf.runtime.MakeDefinitions.*;
import static me.bechberger.ebpf.runtime.MapDefinitions.*;
import static me.bechberger.ebpf.runtime.MapleDefinitions.*;
import static me.bechberger.ebpf.runtime.MarkDefinitions.*;
import static me.bechberger.ebpf.runtime.MasDefinitions.*;
import static me.bechberger.ebpf.runtime.MatchDefinitions.*;
import static me.bechberger.ebpf.runtime.Max310xDefinitions.*;
import static me.bechberger.ebpf.runtime.Max77693Definitions.*;
import static me.bechberger.ebpf.runtime.Max8925Definitions.*;
import static me.bechberger.ebpf.runtime.Max8997Definitions.*;
import static me.bechberger.ebpf.runtime.Max8998Definitions.*;
import static me.bechberger.ebpf.runtime.MaxDefinitions.*;
import static me.bechberger.ebpf.runtime.MayDefinitions.*;
import static me.bechberger.ebpf.runtime.MaybeDefinitions.*;
import static me.bechberger.ebpf.runtime.MbDefinitions.*;
import static me.bechberger.ebpf.runtime.MbmDefinitions.*;
import static me.bechberger.ebpf.runtime.MboxDefinitions.*;
import static me.bechberger.ebpf.runtime.MceDefinitions.*;
import static me.bechberger.ebpf.runtime.McheckDefinitions.*;
import static me.bechberger.ebpf.runtime.MciDefinitions.*;
import static me.bechberger.ebpf.runtime.MctpDefinitions.*;
import static me.bechberger.ebpf.runtime.MctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.MdDefinitions.*;
import static me.bechberger.ebpf.runtime.MddevDefinitions.*;
import static me.bechberger.ebpf.runtime.MdioDefinitions.*;
import static me.bechberger.ebpf.runtime.MdiobusDefinitions.*;
import static me.bechberger.ebpf.runtime.MemDefinitions.*;
import static me.bechberger.ebpf.runtime.MemblockDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcgDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcpyDefinitions.*;
import static me.bechberger.ebpf.runtime.MemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MemoryDefinitions.*;
import static me.bechberger.ebpf.runtime.MempoolDefinitions.*;
import static me.bechberger.ebpf.runtime.MemtypeDefinitions.*;
import static me.bechberger.ebpf.runtime.MigrateDefinitions.*;
import static me.bechberger.ebpf.runtime.MinDefinitions.*;
import static me.bechberger.ebpf.runtime.MipiDefinitions.*;
import static me.bechberger.ebpf.runtime.MiscDefinitions.*;
import static me.bechberger.ebpf.runtime.MldDefinitions.*;
import static me.bechberger.ebpf.runtime.MlsDefinitions.*;
import static me.bechberger.ebpf.runtime.MmDefinitions.*;
import static me.bechberger.ebpf.runtime.MmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MmcDefinitions.*;
import static me.bechberger.ebpf.runtime.MmioDefinitions.*;
import static me.bechberger.ebpf.runtime.MmuDefinitions.*;
import static me.bechberger.ebpf.runtime.MntDefinitions.*;
import static me.bechberger.ebpf.runtime.ModDefinitions.*;
import static me.bechberger.ebpf.runtime.ModuleDefinitions.*;
import static me.bechberger.ebpf.runtime.MountDefinitions.*;
import static me.bechberger.ebpf.runtime.MousedevDefinitions.*;
import static me.bechberger.ebpf.runtime.MoveDefinitions.*;
import static me.bechberger.ebpf.runtime.MpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpageDefinitions.*;
import static me.bechberger.ebpf.runtime.MpiDefinitions.*;
import static me.bechberger.ebpf.runtime.MpihelpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpolDefinitions.*;
import static me.bechberger.ebpf.runtime.MptcpDefinitions.*;
import static me.bechberger.ebpf.runtime.MqDefinitions.*;
import static me.bechberger.ebpf.runtime.MqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.MrDefinitions.*;
import static me.bechberger.ebpf.runtime.MsgDefinitions.*;
import static me.bechberger.ebpf.runtime.MsiDefinitions.*;
import static me.bechberger.ebpf.runtime.MsrDefinitions.*;
import static me.bechberger.ebpf.runtime.MtDefinitions.*;
import static me.bechberger.ebpf.runtime.MtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.MtrrDefinitions.*;
import static me.bechberger.ebpf.runtime.MutexDefinitions.*;
import static me.bechberger.ebpf.runtime.NDefinitions.*;
import static me.bechberger.ebpf.runtime.NapiDefinitions.*;
import static me.bechberger.ebpf.runtime.NativeDefinitions.*;
import static me.bechberger.ebpf.runtime.NbconDefinitions.*;
import static me.bechberger.ebpf.runtime.NcsiDefinitions.*;
import static me.bechberger.ebpf.runtime.NdDefinitions.*;
import static me.bechberger.ebpf.runtime.NdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.NeighDefinitions.*;
import static me.bechberger.ebpf.runtime.NetDefinitions.*;
import static me.bechberger.ebpf.runtime.NetdevDefinitions.*;
import static me.bechberger.ebpf.runtime.NetifDefinitions.*;
import static me.bechberger.ebpf.runtime.NetkitDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlblDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.NetnsDefinitions.*;
import static me.bechberger.ebpf.runtime.NetpollDefinitions.*;
import static me.bechberger.ebpf.runtime.NewDefinitions.*;
import static me.bechberger.ebpf.runtime.NextDefinitions.*;
import static me.bechberger.ebpf.runtime.NexthopDefinitions.*;
import static me.bechberger.ebpf.runtime.NfDefinitions.*;
import static me.bechberger.ebpf.runtime.Nfs4Definitions.*;
import static me.bechberger.ebpf.runtime.NfsDefinitions.*;
import static me.bechberger.ebpf.runtime.NhDefinitions.*;
import static me.bechberger.ebpf.runtime.NhmexDefinitions.*;
import static me.bechberger.ebpf.runtime.Nl80211Definitions.*;
import static me.bechberger.ebpf.runtime.NlaDefinitions.*;
import static me.bechberger.ebpf.runtime.NmiDefinitions.*;
import static me.bechberger.ebpf.runtime.NoDefinitions.*;
import static me.bechberger.ebpf.runtime.NodeDefinitions.*;
import static me.bechberger.ebpf.runtime.NoopDefinitions.*;
import static me.bechberger.ebpf.runtime.NotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.NrDefinitions.*;
import static me.bechberger.ebpf.runtime.NsDefinitions.*;
import static me.bechberger.ebpf.runtime.NullDefinitions.*;
import static me.bechberger.ebpf.runtime.NumaDefinitions.*;
import static me.bechberger.ebpf.runtime.NumachipDefinitions.*;
import static me.bechberger.ebpf.runtime.NvdimmDefinitions.*;
import static me.bechberger.ebpf.runtime.NvmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ObjDefinitions.*;
import static me.bechberger.ebpf.runtime.OctepDefinitions.*;
import static me.bechberger.ebpf.runtime.OdDefinitions.*;
import static me.bechberger.ebpf.runtime.OfDefinitions.*;
import static me.bechberger.ebpf.runtime.OhciDefinitions.*;
import static me.bechberger.ebpf.runtime.OldDefinitions.*;
import static me.bechberger.ebpf.runtime.OomDefinitions.*;
import static me.bechberger.ebpf.runtime.OpalDefinitions.*;
import static me.bechberger.ebpf.runtime.OpenDefinitions.*;
import static me.bechberger.ebpf.runtime.OppDefinitions.*;
import static me.bechberger.ebpf.runtime.OsnoiseDefinitions.*;
import static me.bechberger.ebpf.runtime.P4Definitions.*;
import static me.bechberger.ebpf.runtime.PacketDefinitions.*;
import static me.bechberger.ebpf.runtime.PadataDefinitions.*;
import static me.bechberger.ebpf.runtime.PageDefinitions.*;
import static me.bechberger.ebpf.runtime.PagemapDefinitions.*;
import static me.bechberger.ebpf.runtime.PagesDefinitions.*;
import static me.bechberger.ebpf.runtime.PalmasDefinitions.*;
import static me.bechberger.ebpf.runtime.PanelDefinitions.*;
import static me.bechberger.ebpf.runtime.ParamDefinitions.*;
import static me.bechberger.ebpf.runtime.ParseDefinitions.*;
import static me.bechberger.ebpf.runtime.PartDefinitions.*;
import static me.bechberger.ebpf.runtime.PathDefinitions.*;
import static me.bechberger.ebpf.runtime.PcapDefinitions.*;
import static me.bechberger.ebpf.runtime.PccDefinitions.*;
import static me.bechberger.ebpf.runtime.PciDefinitions.*;
import static me.bechberger.ebpf.runtime.PcibiosDefinitions.*;
import static me.bechberger.ebpf.runtime.PcieDefinitions.*;
import static me.bechberger.ebpf.runtime.PciehpDefinitions.*;
import static me.bechberger.ebpf.runtime.PcimDefinitions.*;
import static me.bechberger.ebpf.runtime.PcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PercpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PerfDefinitions.*;
import static me.bechberger.ebpf.runtime.PfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.PfnDefinitions.*;
import static me.bechberger.ebpf.runtime.PhyDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysdevDefinitions.*;
import static me.bechberger.ebpf.runtime.PickDefinitions.*;
import static me.bechberger.ebpf.runtime.PidDefinitions.*;
import static me.bechberger.ebpf.runtime.PidfsDefinitions.*;
import static me.bechberger.ebpf.runtime.PidsDefinitions.*;
import static me.bechberger.ebpf.runtime.PiixDefinitions.*;
import static me.bechberger.ebpf.runtime.PinDefinitions.*;
import static me.bechberger.ebpf.runtime.PinconfDefinitions.*;
import static me.bechberger.ebpf.runtime.PinctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.PingDefinitions.*;
import static me.bechberger.ebpf.runtime.PinmuxDefinitions.*;
import static me.bechberger.ebpf.runtime.PipeDefinitions.*;
import static me.bechberger.ebpf.runtime.PirqDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs1padDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs7Definitions.*;
import static me.bechberger.ebpf.runtime.PlatformDefinitions.*;
import static me.bechberger.ebpf.runtime.PldmfwDefinitions.*;
import static me.bechberger.ebpf.runtime.Pm860xDefinitions.*;
import static me.bechberger.ebpf.runtime.PmDefinitions.*;
import static me.bechberger.ebpf.runtime.PmcDefinitions.*;
import static me.bechberger.ebpf.runtime.PmdDefinitions.*;
import static me.bechberger.ebpf.runtime.PmuDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpacpiDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicyDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicydbDefinitions.*;
import static me.bechberger.ebpf.runtime.PollDefinitions.*;
import static me.bechberger.ebpf.runtime.Poly1305Definitions.*;
import static me.bechberger.ebpf.runtime.PopulateDefinitions.*;
import static me.bechberger.ebpf.runtime.PortDefinitions.*;
import static me.bechberger.ebpf.runtime.PosixDefinitions.*;
import static me.bechberger.ebpf.runtime.PowerDefinitions.*;
import static me.bechberger.ebpf.runtime.PowercapDefinitions.*;
import static me.bechberger.ebpf.runtime.PppDefinitions.*;
import static me.bechberger.ebpf.runtime.PpsDefinitions.*;
import static me.bechberger.ebpf.runtime.PrDefinitions.*;
import static me.bechberger.ebpf.runtime.PrbDefinitions.*;
import static me.bechberger.ebpf.runtime.PreemptDefinitions.*;
import static me.bechberger.ebpf.runtime.PrepareDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintkDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbeDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbestubDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcessDefinitions.*;
import static me.bechberger.ebpf.runtime.ProfileDefinitions.*;
import static me.bechberger.ebpf.runtime.ProgDefinitions.*;
import static me.bechberger.ebpf.runtime.PropagateDefinitions.*;
import static me.bechberger.ebpf.runtime.ProtoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ps2Definitions.*;
import static me.bechberger.ebpf.runtime.PseDefinitions.*;
import static me.bechberger.ebpf.runtime.PseudoDefinitions.*;
import static me.bechberger.ebpf.runtime.PsiDefinitions.*;
import static me.bechberger.ebpf.runtime.PskbDefinitions.*;
import static me.bechberger.ebpf.runtime.PstoreDefinitions.*;
import static me.bechberger.ebpf.runtime.PtDefinitions.*;
import static me.bechberger.ebpf.runtime.PtdumpDefinitions.*;
import static me.bechberger.ebpf.runtime.PteDefinitions.*;
import static me.bechberger.ebpf.runtime.PtiDefinitions.*;
import static me.bechberger.ebpf.runtime.PtpDefinitions.*;
import static me.bechberger.ebpf.runtime.PtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.PtyDefinitions.*;
import static me.bechberger.ebpf.runtime.PushDefinitions.*;
import static me.bechberger.ebpf.runtime.PutDefinitions.*;
import static me.bechberger.ebpf.runtime.PvDefinitions.*;
import static me.bechberger.ebpf.runtime.PvclockDefinitions.*;
import static me.bechberger.ebpf.runtime.PwmDefinitions.*;
import static me.bechberger.ebpf.runtime.QdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.QhDefinitions.*;
import static me.bechberger.ebpf.runtime.QiDefinitions.*;
import static me.bechberger.ebpf.runtime.QueueDefinitions.*;
import static me.bechberger.ebpf.runtime.QuirkDefinitions.*;
import static me.bechberger.ebpf.runtime.QuotaDefinitions.*;
import static me.bechberger.ebpf.runtime.RadixDefinitions.*;
import static me.bechberger.ebpf.runtime.RamfsDefinitions.*;
import static me.bechberger.ebpf.runtime.RandomDefinitions.*;
import static me.bechberger.ebpf.runtime.RangeDefinitions.*;
import static me.bechberger.ebpf.runtime.Raw6Definitions.*;
import static me.bechberger.ebpf.runtime.RawDefinitions.*;
import static me.bechberger.ebpf.runtime.Rawv6Definitions.*;
import static me.bechberger.ebpf.runtime.RbDefinitions.*;
import static me.bechberger.ebpf.runtime.Rc5t583Definitions.*;
import static me.bechberger.ebpf.runtime.RcuDefinitions.*;
import static me.bechberger.ebpf.runtime.RdevDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmacgDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ReadDefinitions.*;
import static me.bechberger.ebpf.runtime.ReclaimDefinitions.*;
import static me.bechberger.ebpf.runtime.RegDefinitions.*;
import static me.bechberger.ebpf.runtime.RegcacheDefinitions.*;
import static me.bechberger.ebpf.runtime.RegisterDefinitions.*;
import static me.bechberger.ebpf.runtime.RegmapDefinitions.*;
import static me.bechberger.ebpf.runtime.RegulatorDefinitions.*;
import static me.bechberger.ebpf.runtime.RelayDefinitions.*;
import static me.bechberger.ebpf.runtime.ReleaseDefinitions.*;
import static me.bechberger.ebpf.runtime.RemapDefinitions.*;
import static me.bechberger.ebpf.runtime.RemoveDefinitions.*;
import static me.bechberger.ebpf.runtime.ReplaceDefinitions.*;
import static me.bechberger.ebpf.runtime.ReportDefinitions.*;
import static me.bechberger.ebpf.runtime.RequestDefinitions.*;
import static me.bechberger.ebpf.runtime.ResctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.ReserveDefinitions.*;
import static me.bechberger.ebpf.runtime.ResetDefinitions.*;
import static me.bechberger.ebpf.runtime.ResourceDefinitions.*;
import static me.bechberger.ebpf.runtime.RestoreDefinitions.*;
import static me.bechberger.ebpf.runtime.RestrictDefinitions.*;
import static me.bechberger.ebpf.runtime.ResumeDefinitions.*;
import static me.bechberger.ebpf.runtime.RethookDefinitions.*;
import static me.bechberger.ebpf.runtime.ReuseportDefinitions.*;
import static me.bechberger.ebpf.runtime.RfkillDefinitions.*;
import static me.bechberger.ebpf.runtime.RhashtableDefinitions.*;
import static me.bechberger.ebpf.runtime.RingDefinitions.*;
import static me.bechberger.ebpf.runtime.RingbufDefinitions.*;
import static me.bechberger.ebpf.runtime.RioDefinitions.*;
import static me.bechberger.ebpf.runtime.RngDefinitions.*;
import static me.bechberger.ebpf.runtime.RoleDefinitions.*;
import static me.bechberger.ebpf.runtime.RpcDefinitions.*;
import static me.bechberger.ebpf.runtime.RpmDefinitions.*;
import static me.bechberger.ebpf.runtime.RprocDefinitions.*;
import static me.bechberger.ebpf.runtime.RqDefinitions.*;
import static me.bechberger.ebpf.runtime.RsaDefinitions.*;
import static me.bechberger.ebpf.runtime.RsassaDefinitions.*;
import static me.bechberger.ebpf.runtime.RseqDefinitions.*;
import static me.bechberger.ebpf.runtime.RssDefinitions.*;
import static me.bechberger.ebpf.runtime.Rt6Definitions.*;
import static me.bechberger.ebpf.runtime.RtDefinitions.*;
import static me.bechberger.ebpf.runtime.RtcDefinitions.*;
import static me.bechberger.ebpf.runtime.RtmDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnlDefinitions.*;
import static me.bechberger.ebpf.runtime.RunDefinitions.*;
import static me.bechberger.ebpf.runtime.RustDefinitions.*;
import static me.bechberger.ebpf.runtime.RvDefinitions.*;
import static me.bechberger.ebpf.runtime.RxDefinitions.*;
import static me.bechberger.ebpf.runtime.SDefinitions.*;
import static me.bechberger.ebpf.runtime.SataDefinitions.*;
import static me.bechberger.ebpf.runtime.SaveDefinitions.*;
import static me.bechberger.ebpf.runtime.SavedDefinitions.*;
import static me.bechberger.ebpf.runtime.SbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.ScanDefinitions.*;
import static me.bechberger.ebpf.runtime.SccnxpDefinitions.*;
import static me.bechberger.ebpf.runtime.SchedDefinitions.*;
import static me.bechberger.ebpf.runtime.ScheduleDefinitions.*;
import static me.bechberger.ebpf.runtime.ScmDefinitions.*;
import static me.bechberger.ebpf.runtime.ScsiDefinitions.*;
import static me.bechberger.ebpf.runtime.SctpDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.SdDefinitions.*;
import static me.bechberger.ebpf.runtime.SdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SdioDefinitions.*;
import static me.bechberger.ebpf.runtime.SeccompDefinitions.*;
import static me.bechberger.ebpf.runtime.SecurityDefinitions.*;
import static me.bechberger.ebpf.runtime.Seg6Definitions.*;
import static me.bechberger.ebpf.runtime.SelDefinitions.*;
import static me.bechberger.ebpf.runtime.SelectDefinitions.*;
import static me.bechberger.ebpf.runtime.SelinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.SendDefinitions.*;
import static me.bechberger.ebpf.runtime.SeqDefinitions.*;
import static me.bechberger.ebpf.runtime.SerdevDefinitions.*;
import static me.bechberger.ebpf.runtime.Serial8250Definitions.*;
import static me.bechberger.ebpf.runtime.SerialDefinitions.*;
import static me.bechberger.ebpf.runtime.SerioDefinitions.*;
import static me.bechberger.ebpf.runtime.SetDefinitions.*;
import static me.bechberger.ebpf.runtime.SetupDefinitions.*;
import static me.bechberger.ebpf.runtime.SevDefinitions.*;
import static me.bechberger.ebpf.runtime.SfpDefinitions.*;
import static me.bechberger.ebpf.runtime.SgDefinitions.*;
import static me.bechberger.ebpf.runtime.SgxDefinitions.*;
import static me.bechberger.ebpf.runtime.Sha1Definitions.*;
import static me.bechberger.ebpf.runtime.Sha256Definitions.*;
import static me.bechberger.ebpf.runtime.Sha512Definitions.*;
import static me.bechberger.ebpf.runtime.ShashDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ShouldDefinitions.*;
import static me.bechberger.ebpf.runtime.ShowDefinitions.*;
import static me.bechberger.ebpf.runtime.ShpchpDefinitions.*;
import static me.bechberger.ebpf.runtime.ShrinkDefinitions.*;
import static me.bechberger.ebpf.runtime.SidtabDefinitions.*;
import static me.bechberger.ebpf.runtime.SimpleDefinitions.*;
import static me.bechberger.ebpf.runtime.SingleDefinitions.*;
import static me.bechberger.ebpf.runtime.SisDefinitions.*;
import static me.bechberger.ebpf.runtime.SkDefinitions.*;
import static me.bechberger.ebpf.runtime.SkbDefinitions.*;
import static me.bechberger.ebpf.runtime.SkcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.SkxDefinitions.*;
import static me.bechberger.ebpf.runtime.SlabDefinitions.*;
import static me.bechberger.ebpf.runtime.SmackDefinitions.*;
import static me.bechberger.ebpf.runtime.SmeDefinitions.*;
import static me.bechberger.ebpf.runtime.SmkDefinitions.*;
import static me.bechberger.ebpf.runtime.SmpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnapshotDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbepDefinitions.*;
import static me.bechberger.ebpf.runtime.SnpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnrDefinitions.*;
import static me.bechberger.ebpf.runtime.SocDefinitions.*;
import static me.bechberger.ebpf.runtime.SockDefinitions.*;
import static me.bechberger.ebpf.runtime.SoftwareDefinitions.*;
import static me.bechberger.ebpf.runtime.SparseDefinitions.*;
import static me.bechberger.ebpf.runtime.SpiDefinitions.*;
import static me.bechberger.ebpf.runtime.SpliceDefinitions.*;
import static me.bechberger.ebpf.runtime.SplitDefinitions.*;
import static me.bechberger.ebpf.runtime.SprDefinitions.*;
import static me.bechberger.ebpf.runtime.SquashfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SrDefinitions.*;
import static me.bechberger.ebpf.runtime.SramDefinitions.*;
import static me.bechberger.ebpf.runtime.SrcuDefinitions.*;
import static me.bechberger.ebpf.runtime.SriovDefinitions.*;
import static me.bechberger.ebpf.runtime.StackDefinitions.*;
import static me.bechberger.ebpf.runtime.StartDefinitions.*;
import static me.bechberger.ebpf.runtime.StatDefinitions.*;
import static me.bechberger.ebpf.runtime.StaticDefinitions.*;
import static me.bechberger.ebpf.runtime.StatsDefinitions.*;
import static me.bechberger.ebpf.runtime.StopDefinitions.*;
import static me.bechberger.ebpf.runtime.StoreDefinitions.*;
import static me.bechberger.ebpf.runtime.StripeDefinitions.*;
import static me.bechberger.ebpf.runtime.StrpDefinitions.*;
import static me.bechberger.ebpf.runtime.SubflowDefinitions.*;
import static me.bechberger.ebpf.runtime.SubmitDefinitions.*;
import static me.bechberger.ebpf.runtime.SugovDefinitions.*;
import static me.bechberger.ebpf.runtime.SuperDefinitions.*;
import static me.bechberger.ebpf.runtime.SuspendDefinitions.*;
import static me.bechberger.ebpf.runtime.SvcDefinitions.*;
import static me.bechberger.ebpf.runtime.SvsmDefinitions.*;
import static me.bechberger.ebpf.runtime.SwDefinitions.*;
import static me.bechberger.ebpf.runtime.SwapDefinitions.*;
import static me.bechberger.ebpf.runtime.SwiotlbDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SwsuspDefinitions.*;
import static me.bechberger.ebpf.runtime.Sx150xDefinitions.*;
import static me.bechberger.ebpf.runtime.SyncDefinitions.*;
import static me.bechberger.ebpf.runtime.SynchronizeDefinitions.*;
import static me.bechberger.ebpf.runtime.SynthDefinitions.*;
import static me.bechberger.ebpf.runtime.SysDefinitions.*;
import static me.bechberger.ebpf.runtime.SyscallDefinitions.*;
import static me.bechberger.ebpf.runtime.SysctlDefinitions.*;
import static me.bechberger.ebpf.runtime.SysfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SysrqDefinitions.*;
import static me.bechberger.ebpf.runtime.SystemDefinitions.*;
import static me.bechberger.ebpf.runtime.SysvecDefinitions.*;
import static me.bechberger.ebpf.runtime.TargetDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskletDefinitions.*;
import static me.bechberger.ebpf.runtime.TbootDefinitions.*;
import static me.bechberger.ebpf.runtime.TcDefinitions.*;
import static me.bechberger.ebpf.runtime.TcfDefinitions.*;
import static me.bechberger.ebpf.runtime.TcpDefinitions.*;
import static me.bechberger.ebpf.runtime.TcxDefinitions.*;
import static me.bechberger.ebpf.runtime.TdhDefinitions.*;
import static me.bechberger.ebpf.runtime.TdxDefinitions.*;
import static me.bechberger.ebpf.runtime.TestDefinitions.*;
import static me.bechberger.ebpf.runtime.TextDefinitions.*;
import static me.bechberger.ebpf.runtime.TgDefinitions.*;
import static me.bechberger.ebpf.runtime.ThermalDefinitions.*;
import static me.bechberger.ebpf.runtime.ThreadDefinitions.*;
import static me.bechberger.ebpf.runtime.ThrotlDefinitions.*;
import static me.bechberger.ebpf.runtime.TickDefinitions.*;
import static me.bechberger.ebpf.runtime.TimekeepingDefinitions.*;
import static me.bechberger.ebpf.runtime.TimensDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerfdDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerlatDefinitions.*;
import static me.bechberger.ebpf.runtime.TkDefinitions.*;
import static me.bechberger.ebpf.runtime.TlbDefinitions.*;
import static me.bechberger.ebpf.runtime.TlsDefinitions.*;
import static me.bechberger.ebpf.runtime.TmigrDefinitions.*;
import static me.bechberger.ebpf.runtime.TnumDefinitions.*;
import static me.bechberger.ebpf.runtime.ToDefinitions.*;
import static me.bechberger.ebpf.runtime.TomoyoDefinitions.*;
import static me.bechberger.ebpf.runtime.TopologyDefinitions.*;
import static me.bechberger.ebpf.runtime.TouchDefinitions.*;
import static me.bechberger.ebpf.runtime.TpacketDefinitions.*;
import static me.bechberger.ebpf.runtime.Tpm1Definitions.*;
import static me.bechberger.ebpf.runtime.Tpm2Definitions.*;
import static me.bechberger.ebpf.runtime.TpmDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps6586xDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps65910Definitions.*;
import static me.bechberger.ebpf.runtime.TraceDefinitions.*;
import static me.bechberger.ebpf.runtime.TracefsDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceiterDefinitions.*;
import static me.bechberger.ebpf.runtime.TracepointDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.TracerDefinitions.*;
import static me.bechberger.ebpf.runtime.TracingDefinitions.*;
import static me.bechberger.ebpf.runtime.TransportDefinitions.*;
import static me.bechberger.ebpf.runtime.TrieDefinitions.*;
import static me.bechberger.ebpf.runtime.TruncateDefinitions.*;
import static me.bechberger.ebpf.runtime.TrustedDefinitions.*;
import static me.bechberger.ebpf.runtime.TryDefinitions.*;
import static me.bechberger.ebpf.runtime.TscDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyportDefinitions.*;
import static me.bechberger.ebpf.runtime.TunDefinitions.*;
import static me.bechberger.ebpf.runtime.Twl4030Definitions.*;
import static me.bechberger.ebpf.runtime.Twl6040Definitions.*;
import static me.bechberger.ebpf.runtime.TwlDefinitions.*;
import static me.bechberger.ebpf.runtime.TxDefinitions.*;
import static me.bechberger.ebpf.runtime.TypeDefinitions.*;
import static me.bechberger.ebpf.runtime.UDefinitions.*;
import static me.bechberger.ebpf.runtime.UartDefinitions.*;
import static me.bechberger.ebpf.runtime.UbsanDefinitions.*;
import static me.bechberger.ebpf.runtime.Udp4Definitions.*;
import static me.bechberger.ebpf.runtime.Udp6Definitions.*;
import static me.bechberger.ebpf.runtime.UdpDefinitions.*;
import static me.bechberger.ebpf.runtime.Udpv6Definitions.*;
import static me.bechberger.ebpf.runtime.UhciDefinitions.*;
import static me.bechberger.ebpf.runtime.UinputDefinitions.*;
import static me.bechberger.ebpf.runtime.UncoreDefinitions.*;
import static me.bechberger.ebpf.runtime.Univ8250Definitions.*;
import static me.bechberger.ebpf.runtime.UnixDefinitions.*;
import static me.bechberger.ebpf.runtime.UnlockDefinitions.*;
import static me.bechberger.ebpf.runtime.UnmapDefinitions.*;
import static me.bechberger.ebpf.runtime.UnregisterDefinitions.*;
import static me.bechberger.ebpf.runtime.UpdateDefinitions.*;
import static me.bechberger.ebpf.runtime.UprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbdevfsDefinitions.*;
import static me.bechberger.ebpf.runtime.UserDefinitions.*;
import static me.bechberger.ebpf.runtime.UserfaultfdDefinitions.*;
import static me.bechberger.ebpf.runtime.Utf8Definitions.*;
import static me.bechberger.ebpf.runtime.UvDefinitions.*;
import static me.bechberger.ebpf.runtime.UvhDefinitions.*;
import static me.bechberger.ebpf.runtime.ValidateDefinitions.*;
import static me.bechberger.ebpf.runtime.VcDefinitions.*;
import static me.bechberger.ebpf.runtime.VcapDefinitions.*;
import static me.bechberger.ebpf.runtime.VcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.VcsDefinitions.*;
import static me.bechberger.ebpf.runtime.VdsoDefinitions.*;
import static me.bechberger.ebpf.runtime.VerifyDefinitions.*;
import static me.bechberger.ebpf.runtime.VfatDefinitions.*;
import static me.bechberger.ebpf.runtime.VfsDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaconDefinitions.*;
import static me.bechberger.ebpf.runtime.ViaDefinitions.*;
import static me.bechberger.ebpf.runtime.ViommuDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtblkDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtioDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtnetDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtscsiDefinitions.*;
import static me.bechberger.ebpf.runtime.VlanDefinitions.*;
import static me.bechberger.ebpf.runtime.VliDefinitions.*;
import static me.bechberger.ebpf.runtime.VmaDefinitions.*;
import static me.bechberger.ebpf.runtime.VmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.VmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmeDefinitions.*;
import static me.bechberger.ebpf.runtime.VmemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmpressureDefinitions.*;
import static me.bechberger.ebpf.runtime.VmstatDefinitions.*;
import static me.bechberger.ebpf.runtime.VmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.VpDefinitions.*;
import static me.bechberger.ebpf.runtime.VringDefinitions.*;
import static me.bechberger.ebpf.runtime.VtDefinitions.*;
import static me.bechberger.ebpf.runtime.WaitDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeupDefinitions.*;
import static me.bechberger.ebpf.runtime.WalkDefinitions.*;
import static me.bechberger.ebpf.runtime.WarnDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchdogDefinitions.*;
import static me.bechberger.ebpf.runtime.WbDefinitions.*;
import static me.bechberger.ebpf.runtime.WbtDefinitions.*;
import static me.bechberger.ebpf.runtime.WiphyDefinitions.*;
import static me.bechberger.ebpf.runtime.WirelessDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm831xDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm8350Definitions.*;
import static me.bechberger.ebpf.runtime.WorkqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.WpDefinitions.*;
import static me.bechberger.ebpf.runtime.WqDefinitions.*;
import static me.bechberger.ebpf.runtime.WriteDefinitions.*;
import static me.bechberger.ebpf.runtime.WritebackDefinitions.*;
import static me.bechberger.ebpf.runtime.WwDefinitions.*;
import static me.bechberger.ebpf.runtime.X2apicDefinitions.*;
import static me.bechberger.ebpf.runtime.X509Definitions.*;
import static me.bechberger.ebpf.runtime.X64Definitions.*;
import static me.bechberger.ebpf.runtime.X86Definitions.*;
import static me.bechberger.ebpf.runtime.XaDefinitions.*;
import static me.bechberger.ebpf.runtime.XasDefinitions.*;
import static me.bechberger.ebpf.runtime.XattrDefinitions.*;
import static me.bechberger.ebpf.runtime.XbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdpDefinitions.*;
import static me.bechberger.ebpf.runtime.XenDefinitions.*;
import static me.bechberger.ebpf.runtime.XenbusDefinitions.*;
import static me.bechberger.ebpf.runtime.XennetDefinitions.*;
import static me.bechberger.ebpf.runtime.XenpfDefinitions.*;
import static me.bechberger.ebpf.runtime.Xfrm4Definitions.*;
import static me.bechberger.ebpf.runtime.Xfrm6Definitions.*;
import static me.bechberger.ebpf.runtime.XfrmDefinitions.*;
import static me.bechberger.ebpf.runtime.XhciDefinitions.*;
import static me.bechberger.ebpf.runtime.XpDefinitions.*;
import static me.bechberger.ebpf.runtime.XsDefinitions.*;
import static me.bechberger.ebpf.runtime.XskDefinitions.*;
import static me.bechberger.ebpf.runtime.XtsDefinitions.*;
import static me.bechberger.ebpf.runtime.XzDefinitions.*;
import static me.bechberger.ebpf.runtime.ZapDefinitions.*;
import static me.bechberger.ebpf.runtime.ZlibDefinitions.*;
import static me.bechberger.ebpf.runtime.ZoneDefinitions.*;
import static me.bechberger.ebpf.runtime.ZpoolDefinitions.*;
import static me.bechberger.ebpf.runtime.ZsDefinitions.*;
import static me.bechberger.ebpf.runtime.ZstdDefinitions.*;
import static me.bechberger.ebpf.runtime.ZswapDefinitions.*;
import static me.bechberger.ebpf.runtime.misc.*;
import static me.bechberger.ebpf.runtime.runtime.*;

/**
 * Generated class for BPF runtime types that start with vm
 */
@java.lang.SuppressWarnings("unused")
public final class VmDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __vm_enough_memory(Ptr<mm_struct> mm, long pages, int cap_sys_admin) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int __vm_insert_mixed(Ptr<vm_area_struct> vma,
      @Unsigned long addr, @Unsigned long pfn, boolean mkwrite) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __vm_map_pages(Ptr<vm_area_struct> vma, Ptr<Ptr<page>> pages,
      @Unsigned long num, @Unsigned long offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __vm_munmap(@Unsigned long start, @Unsigned long len, boolean unlock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void _vm_unmap_aliases(@Unsigned long start, @Unsigned long end, int flush) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vm_area_add_early(Ptr<vm_struct> vm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<vm_area_struct> vm_area_alloc(Ptr<mm_struct> mm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<vm_area_struct> vm_area_dup(Ptr<vm_area_struct> orig) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vm_area_free(Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("vm_area_init_from((const struct vm_area_struct*)$arg1, $arg2)")
  public static void vm_area_init_from(Ptr<vm_area_struct> src, Ptr<vm_area_struct> dest) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vm_area_map_pages(Ptr<vm_struct> area, @Unsigned long start, @Unsigned long end,
      Ptr<Ptr<page>> pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vm_area_register_early(Ptr<vm_struct> vm, @Unsigned long align) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vm_area_unmap_pages(Ptr<vm_struct> area, @Unsigned long start,
      @Unsigned long end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vm_brk_flags(@Unsigned long addr, @Unsigned long request,
      @Unsigned @OriginalName("vm_flags_t") long vm_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)vm_bus_name($arg1))")
  public static String vm_bus_name(Ptr<virtio_device> vdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("vm_cmdline_get($arg1, (const struct kernel_param*)$arg2)")
  public static int vm_cmdline_get(String buffer, Ptr<kernel_param> kp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vm_cmdline_get_device(Ptr<device> dev, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("vm_cmdline_set((const u8*)$arg1, (const struct kernel_param*)$arg2)")
  public static int vm_cmdline_set(String device, Ptr<kernel_param> kp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long vm_commit_limit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vm_del_vqs(Ptr<virtio_device> vdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vm_events_fold_cpu(int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vm_finalize_features(Ptr<virtio_device> vdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vm_find_vqs(Ptr<virtio_device> vdev, @Unsigned int nvqs,
      Ptr<Ptr<virtqueue>> vqs, Ptr<virtqueue_info> vqs_info, Ptr<irq_affinity> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int vm_generation(Ptr<virtio_device> vdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vm_get(Ptr<virtio_device> vdev, @Unsigned int offset, Ptr<?> buf,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long vm_get_features(Ptr<virtio_device> vdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vm_get_page(Ptr<dpages> dp, Ptr<Ptr<page>> p,
      Ptr<java.lang. @Unsigned Long> len, Ptr<java.lang. @Unsigned Integer> offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("pgprot_t") pgprot vm_get_page_prot(
      @Unsigned @OriginalName("vm_flags_t") long vm_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean vm_get_shm_region(Ptr<virtio_device> vdev, Ptr<virtio_shm_region> region,
      char id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static char vm_get_status(Ptr<virtio_device> vdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vm_insert_page(Ptr<vm_area_struct> vma, @Unsigned long addr, Ptr<page> page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vm_insert_pages(Ptr<vm_area_struct> vma, @Unsigned long addr,
      Ptr<Ptr<page>> pages, Ptr<java.lang. @Unsigned Long> num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("irqreturn_t") irqreturn vm_interrupt(int irq, Ptr<?> opaque) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vm_iomap_memory(Ptr<vm_area_struct> vma,
      @Unsigned @OriginalName("phys_addr_t") long start, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vm_map_pages(Ptr<vm_area_struct> vma, Ptr<Ptr<page>> pages,
      @Unsigned long num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vm_map_pages_zero(Ptr<vm_area_struct> vma, Ptr<Ptr<page>> pages,
      @Unsigned long num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> vm_map_ram(Ptr<Ptr<page>> pages, @Unsigned int count, int node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long vm_memory_committed() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean vm_mixed_zeropage_allowed(Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long vm_mmap(Ptr<file> file, @Unsigned long addr, @Unsigned long len,
      @Unsigned long prot, @Unsigned long flag, @Unsigned long offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long vm_mmap_pgoff(Ptr<file> file, @Unsigned long addr,
      @Unsigned long len, @Unsigned long prot, @Unsigned long flag, @Unsigned long pgoff) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vm_munmap(@Unsigned long start, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vm_next_page(Ptr<dpages> dp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<folio> vm_normal_folio(Ptr<vm_area_struct> vma, @Unsigned long addr,
      pte_t pte) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<folio> vm_normal_folio_pmd(Ptr<vm_area_struct> vma, @Unsigned long addr,
      pmd_t pmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<page> vm_normal_page(Ptr<vm_area_struct> vma, @Unsigned long addr, pte_t pte) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<page> vm_normal_page_pmd(Ptr<vm_area_struct> vma, @Unsigned long addr,
      pmd_t pmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean vm_notify(Ptr<virtqueue> vq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean vm_notify_with_data(Ptr<virtqueue> vq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vm_reset(Ptr<virtio_device> vdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("vm_set($arg1, $arg2, (const void*)$arg3, $arg4)")
  public static void vm_set(Ptr<virtio_device> vdev, @Unsigned int offset, Ptr<?> buf,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vm_set_status(Ptr<virtio_device> vdev, char status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("vm_setup_vq($arg1, $arg2, (void (*)(struct virtqueue*))$arg3, (const u8*)$arg4, $arg5)")
  public static Ptr<virtqueue> vm_setup_vq(Ptr<virtio_device> vdev, @Unsigned int index,
      Ptr<?> callback, String name, boolean ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vm_stat_account(Ptr<mm_struct> mm,
      @Unsigned @OriginalName("vm_flags_t") long flags, long npages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vm_synchronize_cbs(Ptr<virtio_device> vdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vm_unmap_aliases() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("vm_unmap_ram((const void*)$arg1, $arg2)")
  public static void vm_unmap_ram(Ptr<?> mem, @Unsigned int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long vm_unmapped_area(Ptr<vm_unmapped_area_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vm_unregister_cmdline_device(Ptr<device> dev, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vm_area_struct"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vm_area_struct extends Struct {
    @InlineUnion(777)
    public anon_member_of_anon_member_of_vm_area_struct anon0$0;

    @InlineUnion(777)
    public freeptr_t vm_freeptr;

    public Ptr<mm_struct> vm_mm;

    public @OriginalName("pgprot_t") pgprot vm_page_prot;

    @InlineUnion(778)
    public @Unsigned @OriginalName("vm_flags_t") long vm_flags;

    @InlineUnion(778)
    public @Unsigned @OriginalName("vm_flags_t") long __vm_flags;

    public @Unsigned int vm_lock_seq;

    public list_head anon_vma_chain;

    public Ptr<anon_vma> anon_vma;

    public Ptr<vm_operations_struct> vm_ops;

    public @Unsigned long vm_pgoff;

    public Ptr<file> vm_file;

    public Ptr<?> vm_private_data;

    public @OriginalName("atomic_long_t") atomic64_t swap_readahead_info;

    public Ptr<mempolicy> vm_policy;

    public Ptr<vma_numab_state> numab_state;

    public @OriginalName("refcount_t") refcount_struct vm_refcnt;

    public shared_of_vm_area_struct shared;

    public Ptr<anon_vma_name> anon_name;

    public vm_userfaultfd_ctx vm_userfaultfd_ctx;

    public Ptr<pfnmap_track_ctx> pfnmap_track_ctx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vm_struct"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vm_struct extends Struct {
    public Ptr<vm_struct> next;

    public Ptr<?> addr;

    public @Unsigned long size;

    public @Unsigned long flags;

    public Ptr<Ptr<page>> pages;

    public @Unsigned int page_order;

    public @Unsigned int nr_pages;

    public @Unsigned @OriginalName("phys_addr_t") long phys_addr;

    public Ptr<?> caller;

    public @Unsigned long requested_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vm_userfaultfd_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vm_userfaultfd_ctx extends Struct {
    public Ptr<userfaultfd_ctx> ctx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vm_area_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vm_area_desc extends Struct {
    public Ptr<mm_struct> mm;

    public @Unsigned long start;

    public @Unsigned long end;

    public @Unsigned long pgoff;

    public Ptr<file> file;

    public @Unsigned @OriginalName("vm_flags_t") long vm_flags;

    public @OriginalName("pgprot_t") pgprot page_prot;

    public Ptr<vm_operations_struct> vm_ops;

    public Ptr<?> private_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vm_operations_struct"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vm_operations_struct extends Struct {
    public Ptr<?> open;

    public Ptr<?> close;

    public Ptr<?> may_split;

    public Ptr<?> mremap;

    public Ptr<?> mprotect;

    public Ptr<?> fault;

    public Ptr<?> huge_fault;

    public Ptr<?> map_pages;

    public Ptr<?> pagesize;

    public Ptr<?> page_mkwrite;

    public Ptr<?> pfn_mkwrite;

    public Ptr<?> access;

    public Ptr<?> name;

    public Ptr<?> set_policy;

    public Ptr<?> get_policy;

    public Ptr<?> find_special_page;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vm_fault"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vm_fault extends Struct {
    public anon_member_of_vm_fault anon0;

    public fault_flag flags;

    public Ptr<pmd_t> pmd;

    public Ptr<pud_t> pud;

    @InlineUnion(1780)
    public pte_t orig_pte;

    @InlineUnion(1780)
    public pmd_t orig_pmd;

    public Ptr<page> cow_page;

    public Ptr<page> page;

    public Ptr<pte_t> pte;

    public Ptr<@OriginalName("spinlock_t") spinlock> ptl;

    public @OriginalName("pgtable_t") Ptr<page> prealloc_pte;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum vm_fault_reason"
  )
  public enum vm_fault_reason implements Enum<vm_fault_reason>, TypedEnum<vm_fault_reason, java.lang. @Unsigned Integer> {
    /**
     * {@code VM_FAULT_OOM = 1}
     */
    @EnumMember(
        value = 1L,
        name = "VM_FAULT_OOM"
    )
    VM_FAULT_OOM,

    /**
     * {@code VM_FAULT_SIGBUS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "VM_FAULT_SIGBUS"
    )
    VM_FAULT_SIGBUS,

    /**
     * {@code VM_FAULT_MAJOR = 4}
     */
    @EnumMember(
        value = 4L,
        name = "VM_FAULT_MAJOR"
    )
    VM_FAULT_MAJOR,

    /**
     * {@code VM_FAULT_HWPOISON = 16}
     */
    @EnumMember(
        value = 16L,
        name = "VM_FAULT_HWPOISON"
    )
    VM_FAULT_HWPOISON,

    /**
     * {@code VM_FAULT_HWPOISON_LARGE = 32}
     */
    @EnumMember(
        value = 32L,
        name = "VM_FAULT_HWPOISON_LARGE"
    )
    VM_FAULT_HWPOISON_LARGE,

    /**
     * {@code VM_FAULT_SIGSEGV = 64}
     */
    @EnumMember(
        value = 64L,
        name = "VM_FAULT_SIGSEGV"
    )
    VM_FAULT_SIGSEGV,

    /**
     * {@code VM_FAULT_NOPAGE = 256}
     */
    @EnumMember(
        value = 256L,
        name = "VM_FAULT_NOPAGE"
    )
    VM_FAULT_NOPAGE,

    /**
     * {@code VM_FAULT_LOCKED = 512}
     */
    @EnumMember(
        value = 512L,
        name = "VM_FAULT_LOCKED"
    )
    VM_FAULT_LOCKED,

    /**
     * {@code VM_FAULT_RETRY = 1024}
     */
    @EnumMember(
        value = 1024L,
        name = "VM_FAULT_RETRY"
    )
    VM_FAULT_RETRY,

    /**
     * {@code VM_FAULT_FALLBACK = 2048}
     */
    @EnumMember(
        value = 2048L,
        name = "VM_FAULT_FALLBACK"
    )
    VM_FAULT_FALLBACK,

    /**
     * {@code VM_FAULT_DONE_COW = 4096}
     */
    @EnumMember(
        value = 4096L,
        name = "VM_FAULT_DONE_COW"
    )
    VM_FAULT_DONE_COW,

    /**
     * {@code VM_FAULT_NEEDDSYNC = 8192}
     */
    @EnumMember(
        value = 8192L,
        name = "VM_FAULT_NEEDDSYNC"
    )
    VM_FAULT_NEEDDSYNC,

    /**
     * {@code VM_FAULT_COMPLETED = 16384}
     */
    @EnumMember(
        value = 16384L,
        name = "VM_FAULT_COMPLETED"
    )
    VM_FAULT_COMPLETED,

    /**
     * {@code VM_FAULT_HINDEX_MASK = 983040}
     */
    @EnumMember(
        value = 983040L,
        name = "VM_FAULT_HINDEX_MASK"
    )
    VM_FAULT_HINDEX_MASK
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vm_special_mapping"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vm_special_mapping extends Struct {
    public String name;

    public Ptr<Ptr<page>> pages;

    public Ptr<?> fault;

    public Ptr<?> mremap;

    public Ptr<?> close;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum vm_event_item"
  )
  public enum vm_event_item implements Enum<vm_event_item>, TypedEnum<vm_event_item, java.lang. @Unsigned Integer> {
    /**
     * {@code PGPGIN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PGPGIN"
    )
    PGPGIN,

    /**
     * {@code PGPGOUT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PGPGOUT"
    )
    PGPGOUT,

    /**
     * {@code PSWPIN = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PSWPIN"
    )
    PSWPIN,

    /**
     * {@code PSWPOUT = 3}
     */
    @EnumMember(
        value = 3L,
        name = "PSWPOUT"
    )
    PSWPOUT,

    /**
     * {@code PGALLOC_DMA = 4}
     */
    @EnumMember(
        value = 4L,
        name = "PGALLOC_DMA"
    )
    PGALLOC_DMA,

    /**
     * {@code PGALLOC_DMA32 = 5}
     */
    @EnumMember(
        value = 5L,
        name = "PGALLOC_DMA32"
    )
    PGALLOC_DMA32,

    /**
     * {@code PGALLOC_NORMAL = 6}
     */
    @EnumMember(
        value = 6L,
        name = "PGALLOC_NORMAL"
    )
    PGALLOC_NORMAL,

    /**
     * {@code PGALLOC_MOVABLE = 7}
     */
    @EnumMember(
        value = 7L,
        name = "PGALLOC_MOVABLE"
    )
    PGALLOC_MOVABLE,

    /**
     * {@code PGALLOC_DEVICE = 8}
     */
    @EnumMember(
        value = 8L,
        name = "PGALLOC_DEVICE"
    )
    PGALLOC_DEVICE,

    /**
     * {@code ALLOCSTALL_DMA = 9}
     */
    @EnumMember(
        value = 9L,
        name = "ALLOCSTALL_DMA"
    )
    ALLOCSTALL_DMA,

    /**
     * {@code ALLOCSTALL_DMA32 = 10}
     */
    @EnumMember(
        value = 10L,
        name = "ALLOCSTALL_DMA32"
    )
    ALLOCSTALL_DMA32,

    /**
     * {@code ALLOCSTALL_NORMAL = 11}
     */
    @EnumMember(
        value = 11L,
        name = "ALLOCSTALL_NORMAL"
    )
    ALLOCSTALL_NORMAL,

    /**
     * {@code ALLOCSTALL_MOVABLE = 12}
     */
    @EnumMember(
        value = 12L,
        name = "ALLOCSTALL_MOVABLE"
    )
    ALLOCSTALL_MOVABLE,

    /**
     * {@code ALLOCSTALL_DEVICE = 13}
     */
    @EnumMember(
        value = 13L,
        name = "ALLOCSTALL_DEVICE"
    )
    ALLOCSTALL_DEVICE,

    /**
     * {@code PGSCAN_SKIP_DMA = 14}
     */
    @EnumMember(
        value = 14L,
        name = "PGSCAN_SKIP_DMA"
    )
    PGSCAN_SKIP_DMA,

    /**
     * {@code PGSCAN_SKIP_DMA32 = 15}
     */
    @EnumMember(
        value = 15L,
        name = "PGSCAN_SKIP_DMA32"
    )
    PGSCAN_SKIP_DMA32,

    /**
     * {@code PGSCAN_SKIP_NORMAL = 16}
     */
    @EnumMember(
        value = 16L,
        name = "PGSCAN_SKIP_NORMAL"
    )
    PGSCAN_SKIP_NORMAL,

    /**
     * {@code PGSCAN_SKIP_MOVABLE = 17}
     */
    @EnumMember(
        value = 17L,
        name = "PGSCAN_SKIP_MOVABLE"
    )
    PGSCAN_SKIP_MOVABLE,

    /**
     * {@code PGSCAN_SKIP_DEVICE = 18}
     */
    @EnumMember(
        value = 18L,
        name = "PGSCAN_SKIP_DEVICE"
    )
    PGSCAN_SKIP_DEVICE,

    /**
     * {@code PGFREE = 19}
     */
    @EnumMember(
        value = 19L,
        name = "PGFREE"
    )
    PGFREE,

    /**
     * {@code PGACTIVATE = 20}
     */
    @EnumMember(
        value = 20L,
        name = "PGACTIVATE"
    )
    PGACTIVATE,

    /**
     * {@code PGDEACTIVATE = 21}
     */
    @EnumMember(
        value = 21L,
        name = "PGDEACTIVATE"
    )
    PGDEACTIVATE,

    /**
     * {@code PGLAZYFREE = 22}
     */
    @EnumMember(
        value = 22L,
        name = "PGLAZYFREE"
    )
    PGLAZYFREE,

    /**
     * {@code PGFAULT = 23}
     */
    @EnumMember(
        value = 23L,
        name = "PGFAULT"
    )
    PGFAULT,

    /**
     * {@code PGMAJFAULT = 24}
     */
    @EnumMember(
        value = 24L,
        name = "PGMAJFAULT"
    )
    PGMAJFAULT,

    /**
     * {@code PGLAZYFREED = 25}
     */
    @EnumMember(
        value = 25L,
        name = "PGLAZYFREED"
    )
    PGLAZYFREED,

    /**
     * {@code PGREFILL = 26}
     */
    @EnumMember(
        value = 26L,
        name = "PGREFILL"
    )
    PGREFILL,

    /**
     * {@code PGREUSE = 27}
     */
    @EnumMember(
        value = 27L,
        name = "PGREUSE"
    )
    PGREUSE,

    /**
     * {@code PGSTEAL_KSWAPD = 28}
     */
    @EnumMember(
        value = 28L,
        name = "PGSTEAL_KSWAPD"
    )
    PGSTEAL_KSWAPD,

    /**
     * {@code PGSTEAL_DIRECT = 29}
     */
    @EnumMember(
        value = 29L,
        name = "PGSTEAL_DIRECT"
    )
    PGSTEAL_DIRECT,

    /**
     * {@code PGSTEAL_KHUGEPAGED = 30}
     */
    @EnumMember(
        value = 30L,
        name = "PGSTEAL_KHUGEPAGED"
    )
    PGSTEAL_KHUGEPAGED,

    /**
     * {@code PGSTEAL_PROACTIVE = 31}
     */
    @EnumMember(
        value = 31L,
        name = "PGSTEAL_PROACTIVE"
    )
    PGSTEAL_PROACTIVE,

    /**
     * {@code PGSCAN_KSWAPD = 32}
     */
    @EnumMember(
        value = 32L,
        name = "PGSCAN_KSWAPD"
    )
    PGSCAN_KSWAPD,

    /**
     * {@code PGSCAN_DIRECT = 33}
     */
    @EnumMember(
        value = 33L,
        name = "PGSCAN_DIRECT"
    )
    PGSCAN_DIRECT,

    /**
     * {@code PGSCAN_KHUGEPAGED = 34}
     */
    @EnumMember(
        value = 34L,
        name = "PGSCAN_KHUGEPAGED"
    )
    PGSCAN_KHUGEPAGED,

    /**
     * {@code PGSCAN_PROACTIVE = 35}
     */
    @EnumMember(
        value = 35L,
        name = "PGSCAN_PROACTIVE"
    )
    PGSCAN_PROACTIVE,

    /**
     * {@code PGSCAN_DIRECT_THROTTLE = 36}
     */
    @EnumMember(
        value = 36L,
        name = "PGSCAN_DIRECT_THROTTLE"
    )
    PGSCAN_DIRECT_THROTTLE,

    /**
     * {@code PGSCAN_ANON = 37}
     */
    @EnumMember(
        value = 37L,
        name = "PGSCAN_ANON"
    )
    PGSCAN_ANON,

    /**
     * {@code PGSCAN_FILE = 38}
     */
    @EnumMember(
        value = 38L,
        name = "PGSCAN_FILE"
    )
    PGSCAN_FILE,

    /**
     * {@code PGSTEAL_ANON = 39}
     */
    @EnumMember(
        value = 39L,
        name = "PGSTEAL_ANON"
    )
    PGSTEAL_ANON,

    /**
     * {@code PGSTEAL_FILE = 40}
     */
    @EnumMember(
        value = 40L,
        name = "PGSTEAL_FILE"
    )
    PGSTEAL_FILE,

    /**
     * {@code PGSCAN_ZONE_RECLAIM_SUCCESS = 41}
     */
    @EnumMember(
        value = 41L,
        name = "PGSCAN_ZONE_RECLAIM_SUCCESS"
    )
    PGSCAN_ZONE_RECLAIM_SUCCESS,

    /**
     * {@code PGSCAN_ZONE_RECLAIM_FAILED = 42}
     */
    @EnumMember(
        value = 42L,
        name = "PGSCAN_ZONE_RECLAIM_FAILED"
    )
    PGSCAN_ZONE_RECLAIM_FAILED,

    /**
     * {@code PGINODESTEAL = 43}
     */
    @EnumMember(
        value = 43L,
        name = "PGINODESTEAL"
    )
    PGINODESTEAL,

    /**
     * {@code SLABS_SCANNED = 44}
     */
    @EnumMember(
        value = 44L,
        name = "SLABS_SCANNED"
    )
    SLABS_SCANNED,

    /**
     * {@code KSWAPD_INODESTEAL = 45}
     */
    @EnumMember(
        value = 45L,
        name = "KSWAPD_INODESTEAL"
    )
    KSWAPD_INODESTEAL,

    /**
     * {@code KSWAPD_LOW_WMARK_HIT_QUICKLY = 46}
     */
    @EnumMember(
        value = 46L,
        name = "KSWAPD_LOW_WMARK_HIT_QUICKLY"
    )
    KSWAPD_LOW_WMARK_HIT_QUICKLY,

    /**
     * {@code KSWAPD_HIGH_WMARK_HIT_QUICKLY = 47}
     */
    @EnumMember(
        value = 47L,
        name = "KSWAPD_HIGH_WMARK_HIT_QUICKLY"
    )
    KSWAPD_HIGH_WMARK_HIT_QUICKLY,

    /**
     * {@code PAGEOUTRUN = 48}
     */
    @EnumMember(
        value = 48L,
        name = "PAGEOUTRUN"
    )
    PAGEOUTRUN,

    /**
     * {@code PGROTATED = 49}
     */
    @EnumMember(
        value = 49L,
        name = "PGROTATED"
    )
    PGROTATED,

    /**
     * {@code DROP_PAGECACHE = 50}
     */
    @EnumMember(
        value = 50L,
        name = "DROP_PAGECACHE"
    )
    DROP_PAGECACHE,

    /**
     * {@code DROP_SLAB = 51}
     */
    @EnumMember(
        value = 51L,
        name = "DROP_SLAB"
    )
    DROP_SLAB,

    /**
     * {@code OOM_KILL = 52}
     */
    @EnumMember(
        value = 52L,
        name = "OOM_KILL"
    )
    OOM_KILL,

    /**
     * {@code NUMA_PTE_UPDATES = 53}
     */
    @EnumMember(
        value = 53L,
        name = "NUMA_PTE_UPDATES"
    )
    NUMA_PTE_UPDATES,

    /**
     * {@code NUMA_HUGE_PTE_UPDATES = 54}
     */
    @EnumMember(
        value = 54L,
        name = "NUMA_HUGE_PTE_UPDATES"
    )
    NUMA_HUGE_PTE_UPDATES,

    /**
     * {@code NUMA_HINT_FAULTS = 55}
     */
    @EnumMember(
        value = 55L,
        name = "NUMA_HINT_FAULTS"
    )
    NUMA_HINT_FAULTS,

    /**
     * {@code NUMA_HINT_FAULTS_LOCAL = 56}
     */
    @EnumMember(
        value = 56L,
        name = "NUMA_HINT_FAULTS_LOCAL"
    )
    NUMA_HINT_FAULTS_LOCAL,

    /**
     * {@code NUMA_PAGE_MIGRATE = 57}
     */
    @EnumMember(
        value = 57L,
        name = "NUMA_PAGE_MIGRATE"
    )
    NUMA_PAGE_MIGRATE,

    /**
     * {@code PGMIGRATE_SUCCESS = 58}
     */
    @EnumMember(
        value = 58L,
        name = "PGMIGRATE_SUCCESS"
    )
    PGMIGRATE_SUCCESS,

    /**
     * {@code PGMIGRATE_FAIL = 59}
     */
    @EnumMember(
        value = 59L,
        name = "PGMIGRATE_FAIL"
    )
    PGMIGRATE_FAIL,

    /**
     * {@code THP_MIGRATION_SUCCESS = 60}
     */
    @EnumMember(
        value = 60L,
        name = "THP_MIGRATION_SUCCESS"
    )
    THP_MIGRATION_SUCCESS,

    /**
     * {@code THP_MIGRATION_FAIL = 61}
     */
    @EnumMember(
        value = 61L,
        name = "THP_MIGRATION_FAIL"
    )
    THP_MIGRATION_FAIL,

    /**
     * {@code THP_MIGRATION_SPLIT = 62}
     */
    @EnumMember(
        value = 62L,
        name = "THP_MIGRATION_SPLIT"
    )
    THP_MIGRATION_SPLIT,

    /**
     * {@code COMPACTMIGRATE_SCANNED = 63}
     */
    @EnumMember(
        value = 63L,
        name = "COMPACTMIGRATE_SCANNED"
    )
    COMPACTMIGRATE_SCANNED,

    /**
     * {@code COMPACTFREE_SCANNED = 64}
     */
    @EnumMember(
        value = 64L,
        name = "COMPACTFREE_SCANNED"
    )
    COMPACTFREE_SCANNED,

    /**
     * {@code COMPACTISOLATED = 65}
     */
    @EnumMember(
        value = 65L,
        name = "COMPACTISOLATED"
    )
    COMPACTISOLATED,

    /**
     * {@code COMPACTSTALL = 66}
     */
    @EnumMember(
        value = 66L,
        name = "COMPACTSTALL"
    )
    COMPACTSTALL,

    /**
     * {@code COMPACTFAIL = 67}
     */
    @EnumMember(
        value = 67L,
        name = "COMPACTFAIL"
    )
    COMPACTFAIL,

    /**
     * {@code COMPACTSUCCESS = 68}
     */
    @EnumMember(
        value = 68L,
        name = "COMPACTSUCCESS"
    )
    COMPACTSUCCESS,

    /**
     * {@code KCOMPACTD_WAKE = 69}
     */
    @EnumMember(
        value = 69L,
        name = "KCOMPACTD_WAKE"
    )
    KCOMPACTD_WAKE,

    /**
     * {@code KCOMPACTD_MIGRATE_SCANNED = 70}
     */
    @EnumMember(
        value = 70L,
        name = "KCOMPACTD_MIGRATE_SCANNED"
    )
    KCOMPACTD_MIGRATE_SCANNED,

    /**
     * {@code KCOMPACTD_FREE_SCANNED = 71}
     */
    @EnumMember(
        value = 71L,
        name = "KCOMPACTD_FREE_SCANNED"
    )
    KCOMPACTD_FREE_SCANNED,

    /**
     * {@code HTLB_BUDDY_PGALLOC = 72}
     */
    @EnumMember(
        value = 72L,
        name = "HTLB_BUDDY_PGALLOC"
    )
    HTLB_BUDDY_PGALLOC,

    /**
     * {@code HTLB_BUDDY_PGALLOC_FAIL = 73}
     */
    @EnumMember(
        value = 73L,
        name = "HTLB_BUDDY_PGALLOC_FAIL"
    )
    HTLB_BUDDY_PGALLOC_FAIL,

    /**
     * {@code CMA_ALLOC_SUCCESS = 74}
     */
    @EnumMember(
        value = 74L,
        name = "CMA_ALLOC_SUCCESS"
    )
    CMA_ALLOC_SUCCESS,

    /**
     * {@code CMA_ALLOC_FAIL = 75}
     */
    @EnumMember(
        value = 75L,
        name = "CMA_ALLOC_FAIL"
    )
    CMA_ALLOC_FAIL,

    /**
     * {@code UNEVICTABLE_PGCULLED = 76}
     */
    @EnumMember(
        value = 76L,
        name = "UNEVICTABLE_PGCULLED"
    )
    UNEVICTABLE_PGCULLED,

    /**
     * {@code UNEVICTABLE_PGSCANNED = 77}
     */
    @EnumMember(
        value = 77L,
        name = "UNEVICTABLE_PGSCANNED"
    )
    UNEVICTABLE_PGSCANNED,

    /**
     * {@code UNEVICTABLE_PGRESCUED = 78}
     */
    @EnumMember(
        value = 78L,
        name = "UNEVICTABLE_PGRESCUED"
    )
    UNEVICTABLE_PGRESCUED,

    /**
     * {@code UNEVICTABLE_PGMLOCKED = 79}
     */
    @EnumMember(
        value = 79L,
        name = "UNEVICTABLE_PGMLOCKED"
    )
    UNEVICTABLE_PGMLOCKED,

    /**
     * {@code UNEVICTABLE_PGMUNLOCKED = 80}
     */
    @EnumMember(
        value = 80L,
        name = "UNEVICTABLE_PGMUNLOCKED"
    )
    UNEVICTABLE_PGMUNLOCKED,

    /**
     * {@code UNEVICTABLE_PGCLEARED = 81}
     */
    @EnumMember(
        value = 81L,
        name = "UNEVICTABLE_PGCLEARED"
    )
    UNEVICTABLE_PGCLEARED,

    /**
     * {@code UNEVICTABLE_PGSTRANDED = 82}
     */
    @EnumMember(
        value = 82L,
        name = "UNEVICTABLE_PGSTRANDED"
    )
    UNEVICTABLE_PGSTRANDED,

    /**
     * {@code THP_FAULT_ALLOC = 83}
     */
    @EnumMember(
        value = 83L,
        name = "THP_FAULT_ALLOC"
    )
    THP_FAULT_ALLOC,

    /**
     * {@code THP_FAULT_FALLBACK = 84}
     */
    @EnumMember(
        value = 84L,
        name = "THP_FAULT_FALLBACK"
    )
    THP_FAULT_FALLBACK,

    /**
     * {@code THP_FAULT_FALLBACK_CHARGE = 85}
     */
    @EnumMember(
        value = 85L,
        name = "THP_FAULT_FALLBACK_CHARGE"
    )
    THP_FAULT_FALLBACK_CHARGE,

    /**
     * {@code THP_COLLAPSE_ALLOC = 86}
     */
    @EnumMember(
        value = 86L,
        name = "THP_COLLAPSE_ALLOC"
    )
    THP_COLLAPSE_ALLOC,

    /**
     * {@code THP_COLLAPSE_ALLOC_FAILED = 87}
     */
    @EnumMember(
        value = 87L,
        name = "THP_COLLAPSE_ALLOC_FAILED"
    )
    THP_COLLAPSE_ALLOC_FAILED,

    /**
     * {@code THP_FILE_ALLOC = 88}
     */
    @EnumMember(
        value = 88L,
        name = "THP_FILE_ALLOC"
    )
    THP_FILE_ALLOC,

    /**
     * {@code THP_FILE_FALLBACK = 89}
     */
    @EnumMember(
        value = 89L,
        name = "THP_FILE_FALLBACK"
    )
    THP_FILE_FALLBACK,

    /**
     * {@code THP_FILE_FALLBACK_CHARGE = 90}
     */
    @EnumMember(
        value = 90L,
        name = "THP_FILE_FALLBACK_CHARGE"
    )
    THP_FILE_FALLBACK_CHARGE,

    /**
     * {@code THP_FILE_MAPPED = 91}
     */
    @EnumMember(
        value = 91L,
        name = "THP_FILE_MAPPED"
    )
    THP_FILE_MAPPED,

    /**
     * {@code THP_SPLIT_PAGE = 92}
     */
    @EnumMember(
        value = 92L,
        name = "THP_SPLIT_PAGE"
    )
    THP_SPLIT_PAGE,

    /**
     * {@code THP_SPLIT_PAGE_FAILED = 93}
     */
    @EnumMember(
        value = 93L,
        name = "THP_SPLIT_PAGE_FAILED"
    )
    THP_SPLIT_PAGE_FAILED,

    /**
     * {@code THP_DEFERRED_SPLIT_PAGE = 94}
     */
    @EnumMember(
        value = 94L,
        name = "THP_DEFERRED_SPLIT_PAGE"
    )
    THP_DEFERRED_SPLIT_PAGE,

    /**
     * {@code THP_UNDERUSED_SPLIT_PAGE = 95}
     */
    @EnumMember(
        value = 95L,
        name = "THP_UNDERUSED_SPLIT_PAGE"
    )
    THP_UNDERUSED_SPLIT_PAGE,

    /**
     * {@code THP_SPLIT_PMD = 96}
     */
    @EnumMember(
        value = 96L,
        name = "THP_SPLIT_PMD"
    )
    THP_SPLIT_PMD,

    /**
     * {@code THP_SCAN_EXCEED_NONE_PTE = 97}
     */
    @EnumMember(
        value = 97L,
        name = "THP_SCAN_EXCEED_NONE_PTE"
    )
    THP_SCAN_EXCEED_NONE_PTE,

    /**
     * {@code THP_SCAN_EXCEED_SWAP_PTE = 98}
     */
    @EnumMember(
        value = 98L,
        name = "THP_SCAN_EXCEED_SWAP_PTE"
    )
    THP_SCAN_EXCEED_SWAP_PTE,

    /**
     * {@code THP_SCAN_EXCEED_SHARED_PTE = 99}
     */
    @EnumMember(
        value = 99L,
        name = "THP_SCAN_EXCEED_SHARED_PTE"
    )
    THP_SCAN_EXCEED_SHARED_PTE,

    /**
     * {@code THP_SPLIT_PUD = 100}
     */
    @EnumMember(
        value = 100L,
        name = "THP_SPLIT_PUD"
    )
    THP_SPLIT_PUD,

    /**
     * {@code THP_ZERO_PAGE_ALLOC = 101}
     */
    @EnumMember(
        value = 101L,
        name = "THP_ZERO_PAGE_ALLOC"
    )
    THP_ZERO_PAGE_ALLOC,

    /**
     * {@code THP_ZERO_PAGE_ALLOC_FAILED = 102}
     */
    @EnumMember(
        value = 102L,
        name = "THP_ZERO_PAGE_ALLOC_FAILED"
    )
    THP_ZERO_PAGE_ALLOC_FAILED,

    /**
     * {@code THP_SWPOUT = 103}
     */
    @EnumMember(
        value = 103L,
        name = "THP_SWPOUT"
    )
    THP_SWPOUT,

    /**
     * {@code THP_SWPOUT_FALLBACK = 104}
     */
    @EnumMember(
        value = 104L,
        name = "THP_SWPOUT_FALLBACK"
    )
    THP_SWPOUT_FALLBACK,

    /**
     * {@code BALLOON_INFLATE = 105}
     */
    @EnumMember(
        value = 105L,
        name = "BALLOON_INFLATE"
    )
    BALLOON_INFLATE,

    /**
     * {@code BALLOON_DEFLATE = 106}
     */
    @EnumMember(
        value = 106L,
        name = "BALLOON_DEFLATE"
    )
    BALLOON_DEFLATE,

    /**
     * {@code BALLOON_MIGRATE = 107}
     */
    @EnumMember(
        value = 107L,
        name = "BALLOON_MIGRATE"
    )
    BALLOON_MIGRATE,

    /**
     * {@code SWAP_RA = 108}
     */
    @EnumMember(
        value = 108L,
        name = "SWAP_RA"
    )
    SWAP_RA,

    /**
     * {@code SWAP_RA_HIT = 109}
     */
    @EnumMember(
        value = 109L,
        name = "SWAP_RA_HIT"
    )
    SWAP_RA_HIT,

    /**
     * {@code SWPIN_ZERO = 110}
     */
    @EnumMember(
        value = 110L,
        name = "SWPIN_ZERO"
    )
    SWPIN_ZERO,

    /**
     * {@code SWPOUT_ZERO = 111}
     */
    @EnumMember(
        value = 111L,
        name = "SWPOUT_ZERO"
    )
    SWPOUT_ZERO,

    /**
     * {@code KSM_SWPIN_COPY = 112}
     */
    @EnumMember(
        value = 112L,
        name = "KSM_SWPIN_COPY"
    )
    KSM_SWPIN_COPY,

    /**
     * {@code COW_KSM = 113}
     */
    @EnumMember(
        value = 113L,
        name = "COW_KSM"
    )
    COW_KSM,

    /**
     * {@code ZSWPIN = 114}
     */
    @EnumMember(
        value = 114L,
        name = "ZSWPIN"
    )
    ZSWPIN,

    /**
     * {@code ZSWPOUT = 115}
     */
    @EnumMember(
        value = 115L,
        name = "ZSWPOUT"
    )
    ZSWPOUT,

    /**
     * {@code ZSWPWB = 116}
     */
    @EnumMember(
        value = 116L,
        name = "ZSWPWB"
    )
    ZSWPWB,

    /**
     * {@code DIRECT_MAP_LEVEL2_SPLIT = 117}
     */
    @EnumMember(
        value = 117L,
        name = "DIRECT_MAP_LEVEL2_SPLIT"
    )
    DIRECT_MAP_LEVEL2_SPLIT,

    /**
     * {@code DIRECT_MAP_LEVEL3_SPLIT = 118}
     */
    @EnumMember(
        value = 118L,
        name = "DIRECT_MAP_LEVEL3_SPLIT"
    )
    DIRECT_MAP_LEVEL3_SPLIT,

    /**
     * {@code DIRECT_MAP_LEVEL2_COLLAPSE = 119}
     */
    @EnumMember(
        value = 119L,
        name = "DIRECT_MAP_LEVEL2_COLLAPSE"
    )
    DIRECT_MAP_LEVEL2_COLLAPSE,

    /**
     * {@code DIRECT_MAP_LEVEL3_COLLAPSE = 120}
     */
    @EnumMember(
        value = 120L,
        name = "DIRECT_MAP_LEVEL3_COLLAPSE"
    )
    DIRECT_MAP_LEVEL3_COLLAPSE,

    /**
     * {@code NR_VM_EVENT_ITEMS = 121}
     */
    @EnumMember(
        value = 121L,
        name = "NR_VM_EVENT_ITEMS"
    )
    NR_VM_EVENT_ITEMS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vm_unmapped_area_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vm_unmapped_area_info extends Struct {
    public @Unsigned long flags;

    public @Unsigned long length;

    public @Unsigned long low_limit;

    public @Unsigned long high_limit;

    public @Unsigned long align_mask;

    public @Unsigned long align_offset;

    public @Unsigned long start_gap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vm_event_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vm_event_state extends Struct {
    public @Unsigned long @Size(121) [] event;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vm_stack"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vm_stack extends Struct {
    public callback_head rcu;

    public Ptr<vm_struct> stack_vm_area;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum vm_stat_item"
  )
  public enum vm_stat_item implements Enum<vm_stat_item>, TypedEnum<vm_stat_item, java.lang. @Unsigned Integer> {
    /**
     * {@code NR_DIRTY_THRESHOLD = 0}
     */
    @EnumMember(
        value = 0L,
        name = "NR_DIRTY_THRESHOLD"
    )
    NR_DIRTY_THRESHOLD,

    /**
     * {@code NR_DIRTY_BG_THRESHOLD = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NR_DIRTY_BG_THRESHOLD"
    )
    NR_DIRTY_BG_THRESHOLD,

    /**
     * {@code NR_MEMMAP_PAGES = 2}
     */
    @EnumMember(
        value = 2L,
        name = "NR_MEMMAP_PAGES"
    )
    NR_MEMMAP_PAGES,

    /**
     * {@code NR_MEMMAP_BOOT_PAGES = 3}
     */
    @EnumMember(
        value = 3L,
        name = "NR_MEMMAP_BOOT_PAGES"
    )
    NR_MEMMAP_BOOT_PAGES,

    /**
     * {@code NR_VM_STAT_ITEMS = 4}
     */
    @EnumMember(
        value = 4L,
        name = "NR_VM_STAT_ITEMS"
    )
    NR_VM_STAT_ITEMS
  }
}
