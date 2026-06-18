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
import static me.bechberger.ebpf.runtime.VmDefinitions.*;
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
 * Generated class for BPF runtime types that start with tomoyo
 */
@java.lang.SuppressWarnings("unused")
public final class TomoyoDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_add_entry(Ptr<tomoyo_domain_info> domain, String header) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_add_slash(Ptr<tomoyo_path_info> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_addprintf($arg1, $arg2, (const u8*)$arg3, $arg4_)")
  public static void tomoyo_addprintf(String buffer, int len, String fmt,
      java.lang.Object... param3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_address_matches_group((const _Bool)$arg1, (const unsigned int*)$arg2, (const struct tomoyo_group*)$arg3)")
  public static boolean tomoyo_address_matches_group(boolean is_ipv6,
      Ptr<java.lang. @Unsigned @OriginalName("__be32") Integer> address, Ptr<tomoyo_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_assign_domain((const u8*)$arg1, (const _Bool)$arg2)")
  public static Ptr<tomoyo_domain_info> tomoyo_assign_domain(String domainname, boolean transit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_assign_namespace((const u8*)$arg1)")
  public static Ptr<tomoyo_policy_namespace> tomoyo_assign_namespace(String domainname) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_audit_inet_log(Ptr<tomoyo_request_info> r) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_bprm_check_security(Ptr<linux_binprm> bprm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_bprm_committed_creds((const struct linux_binprm*)$arg1)")
  public static void tomoyo_bprm_committed_creds(Ptr<linux_binprm> bprm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_bprm_creds_for_exec(Ptr<linux_binprm> bprm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_check_acl($arg1, (_Bool (*)(struct tomoyo_request_info*, const struct tomoyo_acl_info*))$arg2)")
  public static void tomoyo_check_acl(Ptr<tomoyo_request_info> r, Ptr<?> check_entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_check_env_acl($arg1, (const struct tomoyo_acl_info*)$arg2)")
  public static boolean tomoyo_check_env_acl(Ptr<tomoyo_request_info> r, Ptr<tomoyo_acl_info> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_check_inet_acl($arg1, (const struct tomoyo_acl_info*)$arg2)")
  public static boolean tomoyo_check_inet_acl(Ptr<tomoyo_request_info> r,
      Ptr<tomoyo_acl_info> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_check_inet_address((const struct sockaddr*)$arg1, (const unsigned int)$arg2, (const short unsigned int)$arg3, $arg4)")
  public static int tomoyo_check_inet_address(Ptr<sockaddr> addr, @Unsigned int addr_len,
      @Unsigned short port, Ptr<tomoyo_addr_info> address) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_check_mkdev_acl($arg1, (const struct tomoyo_acl_info*)$arg2)")
  public static boolean tomoyo_check_mkdev_acl(Ptr<tomoyo_request_info> r,
      Ptr<tomoyo_acl_info> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_check_mount_acl($arg1, (const struct tomoyo_acl_info*)$arg2)")
  public static boolean tomoyo_check_mount_acl(Ptr<tomoyo_request_info> r,
      Ptr<tomoyo_acl_info> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_check_open_permission($arg1, (const struct path*)$arg2, (const int)$arg3)")
  public static int tomoyo_check_open_permission(Ptr<tomoyo_domain_info> domain, Ptr<path> path,
      int flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_check_path2_acl($arg1, (const struct tomoyo_acl_info*)$arg2)")
  public static boolean tomoyo_check_path2_acl(Ptr<tomoyo_request_info> r,
      Ptr<tomoyo_acl_info> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_check_path_acl($arg1, (const struct tomoyo_acl_info*)$arg2)")
  public static boolean tomoyo_check_path_acl(Ptr<tomoyo_request_info> r,
      Ptr<tomoyo_acl_info> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_check_path_number_acl($arg1, (const struct tomoyo_acl_info*)$arg2)")
  public static boolean tomoyo_check_path_number_acl(Ptr<tomoyo_request_info> r,
      Ptr<tomoyo_acl_info> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_check_profile() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_check_task_acl($arg1, (const struct tomoyo_acl_info*)$arg2)")
  public static boolean tomoyo_check_task_acl(Ptr<tomoyo_request_info> r,
      Ptr<tomoyo_acl_info> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_check_unix_acl($arg1, (const struct tomoyo_acl_info*)$arg2)")
  public static boolean tomoyo_check_unix_acl(Ptr<tomoyo_request_info> r,
      Ptr<tomoyo_acl_info> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_close_control(Ptr<tomoyo_io_buffer> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_collect_entry() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<tomoyo_condition> tomoyo_commit_condition(Ptr<tomoyo_condition> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_commit_ok($arg1, (const unsigned int)$arg2)")
  public static Ptr<?> tomoyo_commit_ok(Ptr<?> data, @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct tomoyo_path_info*)tomoyo_compare_name_union((const struct tomoyo_path_info*)$arg1, (const struct tomoyo_name_union*)$arg2))")
  public static Ptr<tomoyo_path_info> tomoyo_compare_name_union(Ptr<tomoyo_path_info> name,
      Ptr<tomoyo_name_union> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_compare_number_union((const long unsigned int)$arg1, (const struct tomoyo_number_union*)$arg2)")
  public static boolean tomoyo_compare_number_union(@Unsigned long value,
      Ptr<tomoyo_number_union> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_convert_time(@OriginalName("time64_t") long time64,
      Ptr<tomoyo_time> stamp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_correct_domain((const u8*)$arg1)")
  public static boolean tomoyo_correct_domain(String domainname) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_correct_path((const u8*)$arg1)")
  public static boolean tomoyo_correct_path(String filename) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_correct_path2((const u8*)$arg1, (const long unsigned int)$arg2)")
  public static boolean tomoyo_correct_path2(String filename, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_correct_word((const u8*)$arg1)")
  public static boolean tomoyo_correct_word(String string) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_correct_word2((const u8*)$arg1, $arg2)")
  public static boolean tomoyo_correct_word2(String string, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_create_entry((const u8*)$arg1, (const short unsigned int)$arg2, $arg3, (const u8)$arg4)")
  public static void tomoyo_create_entry(String name, @Unsigned @OriginalName("umode_t") short mode,
      Ptr<dentry> parent, char key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_cred_prepare($arg1, (const struct cred*)$arg2, $arg3)")
  public static int tomoyo_cred_prepare(Ptr<cred> _new, Ptr<cred> old,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_del_acl(Ptr<list_head> element) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_del_condition(Ptr<list_head> element) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<tomoyo_domain_info> tomoyo_domain() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_domain_def((const u8*)$arg1)")
  public static boolean tomoyo_domain_def(String buffer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tomoyo_domain_quota_is_ok(Ptr<tomoyo_request_info> r) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tomoyo_dump_page(Ptr<linux_binprm> bprm, @Unsigned long pos,
      Ptr<tomoyo_page_dump> dump) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_encode((const u8*)$arg1)")
  public static String tomoyo_encode(String str) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_encode2((const u8*)$arg1, $arg2)")
  public static String tomoyo_encode2(String str, int str_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_env_perm($arg1, (const u8*)$arg2)")
  public static int tomoyo_env_perm(Ptr<tomoyo_request_info> r, String env) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_environ(Ptr<tomoyo_execve> ee) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_execute_permission($arg1, (const struct tomoyo_path_info*)$arg2)")
  public static int tomoyo_execute_permission(Ptr<tomoyo_request_info> r,
      Ptr<tomoyo_path_info> filename) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_file_fcntl(Ptr<file> file, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_file_ioctl(Ptr<file> file, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_file_matches_pattern((const u8*)$arg1, (const u8*)$arg2, (const u8*)$arg3, (const u8*)$arg4)")
  public static boolean tomoyo_file_matches_pattern(String filename, String filename_end,
      String pattern, String pattern_end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_file_matches_pattern2((const u8*)$arg1, (const u8*)$arg2, (const u8*)$arg3, (const u8*)$arg4)")
  public static boolean tomoyo_file_matches_pattern2(String filename, String filename_end,
      String pattern, String pattern_end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_file_open(Ptr<file> f) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_file_truncate(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_fill_path_info(Ptr<tomoyo_path_info> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_find_domain((const u8*)$arg1)")
  public static Ptr<tomoyo_domain_info> tomoyo_find_domain(String domainname) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_find_namespace((const u8*)$arg1, (const unsigned int)$arg2)")
  public static Ptr<tomoyo_policy_namespace> tomoyo_find_namespace(String name, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_find_next_domain(Ptr<linux_binprm> bprm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_find_yesno((const u8*)$arg1, (const u8*)$arg2)")
  public static @OriginalName("s8") byte tomoyo_find_yesno(String string, String find) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tomoyo_flush(Ptr<tomoyo_io_buffer> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_gc_thread(Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_get_attributes(Ptr<tomoyo_obj_info> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<tomoyo_condition> tomoyo_get_condition(Ptr<tomoyo_acl_param> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct tomoyo_path_info*)tomoyo_get_domainname($arg1))")
  public static Ptr<tomoyo_path_info> tomoyo_get_domainname(Ptr<tomoyo_acl_param> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct tomoyo_path_info*)tomoyo_get_dqword($arg1))")
  public static Ptr<tomoyo_path_info> tomoyo_get_dqword(String start) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)tomoyo_get_exe())")
  public static String tomoyo_get_exe() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_get_group($arg1, (const u8)$arg2)")
  public static Ptr<tomoyo_group> tomoyo_get_group(Ptr<tomoyo_acl_param> param, char idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_get_local_path($arg1, (const u8*)$arg2, (const int)$arg3)")
  public static String tomoyo_get_local_path(Ptr<dentry> dentry, String buffer, int buflen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_get_mode((const struct tomoyo_policy_namespace*)$arg1, (const u8)$arg2, (const u8)$arg3)")
  public static int tomoyo_get_mode(Ptr<tomoyo_policy_namespace> ns, char profile, char index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct tomoyo_path_info*)tomoyo_get_name((const u8*)$arg1))")
  public static Ptr<tomoyo_path_info> tomoyo_get_name(String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_init_log($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static String tomoyo_init_log(Ptr<tomoyo_request_info> r, int len, String fmt,
      Ptr<__va_list_tag> args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_init_policy_namespace(Ptr<tomoyo_policy_namespace> ns) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_init_request_info($arg1, $arg2, (const u8)$arg3)")
  public static int tomoyo_init_request_info(Ptr<tomoyo_request_info> r,
      Ptr<tomoyo_domain_info> domain, char index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_inode_getattr((const struct path*)$arg1)")
  public static int tomoyo_inode_getattr(Ptr<path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_interface_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_io_printf($arg1, (const u8*)$arg2, $arg3_)")
  public static void tomoyo_io_printf(Ptr<tomoyo_io_buffer> head, String fmt,
      java.lang.Object... param2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_load_builtin_policy() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_load_policy((const u8*)$arg1)")
  public static void tomoyo_load_policy(String filename) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_loader_setup(String str) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tomoyo_memory_ok(Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_merge_inet_acl($arg1, $arg2, (const _Bool)$arg3)")
  public static boolean tomoyo_merge_inet_acl(Ptr<tomoyo_acl_info> a, Ptr<tomoyo_acl_info> b,
      boolean is_delete) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_merge_mkdev_acl($arg1, $arg2, (const _Bool)$arg3)")
  public static boolean tomoyo_merge_mkdev_acl(Ptr<tomoyo_acl_info> a, Ptr<tomoyo_acl_info> b,
      boolean is_delete) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_merge_path2_acl($arg1, $arg2, (const _Bool)$arg3)")
  public static boolean tomoyo_merge_path2_acl(Ptr<tomoyo_acl_info> a, Ptr<tomoyo_acl_info> b,
      boolean is_delete) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_merge_path_acl($arg1, $arg2, (const _Bool)$arg3)")
  public static boolean tomoyo_merge_path_acl(Ptr<tomoyo_acl_info> a, Ptr<tomoyo_acl_info> b,
      boolean is_delete) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_merge_path_number_acl($arg1, $arg2, (const _Bool)$arg3)")
  public static boolean tomoyo_merge_path_number_acl(Ptr<tomoyo_acl_info> a, Ptr<tomoyo_acl_info> b,
      boolean is_delete) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_merge_unix_acl($arg1, $arg2, (const _Bool)$arg3)")
  public static boolean tomoyo_merge_unix_acl(Ptr<tomoyo_acl_info> a, Ptr<tomoyo_acl_info> b,
      boolean is_delete) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_mkdev_perm((const u8)$arg1, (const struct path*)$arg2, (const unsigned int)$arg3, $arg4)")
  public static int tomoyo_mkdev_perm(char operation, Ptr<path> path, @Unsigned int mode,
      @Unsigned int dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_mm_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_mount_permission((const u8*)$arg1, (const struct path*)$arg2, (const u8*)$arg3, $arg4, $arg5)")
  public static int tomoyo_mount_permission(String dev_name, Ptr<path> path, String type,
      @Unsigned long flags, Ptr<?> data_page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_name_used_by_io_buffer((const u8*)$arg1)")
  public static boolean tomoyo_name_used_by_io_buffer(String string) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_normalize_line(String buffer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_notify_gc($arg1, (const _Bool)$arg2)")
  public static void tomoyo_notify_gc(Ptr<tomoyo_io_buffer> head, boolean is_register) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_number_matches_group((const long unsigned int)$arg1, (const long unsigned int)$arg2, (const struct tomoyo_group*)$arg3)")
  public static boolean tomoyo_number_matches_group(@Unsigned long min, @Unsigned long max,
      Ptr<tomoyo_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_numscan((const u8*)$arg1, (const u8*)$arg2, $arg3, (const u8)$arg4)")
  public static boolean tomoyo_numscan(String str, String head, Ptr<java.lang.Integer> width,
      char tail) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_open_control((const u8)$arg1, $arg2)")
  public static int tomoyo_open_control(char type, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tomoyo_parse_ipaddr_union(Ptr<tomoyo_acl_param> param,
      Ptr<tomoyo_ipaddr_union> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tomoyo_parse_name_union(Ptr<tomoyo_acl_param> param,
      Ptr<tomoyo_name_union> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tomoyo_parse_number_union(Ptr<tomoyo_acl_param> param,
      Ptr<tomoyo_number_union> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_parse_policy(Ptr<tomoyo_io_buffer> head, String line) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static char tomoyo_parse_ulong(Ptr<java.lang. @Unsigned Long> result, Ptr<String> str) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_path2_perm((const u8)$arg1, (const struct path*)$arg2, (const struct path*)$arg3)")
  public static int tomoyo_path2_perm(char operation, Ptr<path> path1, Ptr<path> path2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_path_chmod((const struct path*)$arg1, $arg2)")
  public static int tomoyo_path_chmod(Ptr<path> path,
      @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_path_chown((const struct path*)$arg1, $arg2, $arg3)")
  public static int tomoyo_path_chown(Ptr<path> path, kuid_t uid, kgid_t gid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_path_chroot((const struct path*)$arg1)")
  public static int tomoyo_path_chroot(Ptr<path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_path_link($arg1, (const struct path*)$arg2, $arg3)")
  public static int tomoyo_path_link(Ptr<dentry> old_dentry, Ptr<path> new_dir,
      Ptr<dentry> new_dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct tomoyo_path_info*)tomoyo_path_matches_group((const struct tomoyo_path_info*)$arg1, (const struct tomoyo_group*)$arg2))")
  public static Ptr<tomoyo_path_info> tomoyo_path_matches_group(Ptr<tomoyo_path_info> pathname,
      Ptr<tomoyo_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_path_matches_pattern((const struct tomoyo_path_info*)$arg1, (const struct tomoyo_path_info*)$arg2)")
  public static boolean tomoyo_path_matches_pattern(Ptr<tomoyo_path_info> filename,
      Ptr<tomoyo_path_info> pattern) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_path_matches_pattern2((const u8*)$arg1, (const u8*)$arg2)")
  public static boolean tomoyo_path_matches_pattern2(String f, String p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_path_mkdir((const struct path*)$arg1, $arg2, $arg3)")
  public static int tomoyo_path_mkdir(Ptr<path> parent, Ptr<dentry> dentry,
      @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_path_mknod((const struct path*)$arg1, $arg2, $arg3, $arg4)")
  public static int tomoyo_path_mknod(Ptr<path> parent, Ptr<dentry> dentry,
      @Unsigned @OriginalName("umode_t") short mode, @Unsigned int dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_path_number_perm((const u8)$arg1, (const struct path*)$arg2, $arg3)")
  public static int tomoyo_path_number_perm(char type, Ptr<path> path, @Unsigned long number) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_path_perm((const u8)$arg1, (const struct path*)$arg2, (const u8*)$arg3)")
  public static int tomoyo_path_perm(char operation, Ptr<path> path, String target) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_path_permission($arg1, $arg2, (const struct tomoyo_path_info*)$arg3)")
  public static int tomoyo_path_permission(Ptr<tomoyo_request_info> r, char operation,
      Ptr<tomoyo_path_info> filename) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_path_rename((const struct path*)$arg1, $arg2, (const struct path*)$arg3, $arg4, (const unsigned int)$arg5)")
  public static int tomoyo_path_rename(Ptr<path> old_parent, Ptr<dentry> old_dentry,
      Ptr<path> new_parent, Ptr<dentry> new_dentry, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_path_rmdir((const struct path*)$arg1, $arg2)")
  public static int tomoyo_path_rmdir(Ptr<path> parent, Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_path_symlink((const struct path*)$arg1, $arg2, (const u8*)$arg3)")
  public static int tomoyo_path_symlink(Ptr<path> parent, Ptr<dentry> dentry, String old_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_path_truncate((const struct path*)$arg1)")
  public static int tomoyo_path_truncate(Ptr<path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_path_unlink((const struct path*)$arg1, $arg2)")
  public static int tomoyo_path_unlink(Ptr<path> parent, Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_patternize_path($arg1, (const int)$arg2, $arg3)")
  public static void tomoyo_patternize_path(String buffer, int len, String entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_permstr((const u8*)$arg1, (const u8*)$arg2)")
  public static boolean tomoyo_permstr(String string, String keyword) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__poll_t") int tomoyo_poll(Ptr<file> file,
      Ptr<poll_table_struct> wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__poll_t") int tomoyo_poll_control(Ptr<file> file,
      Ptr<poll_table_struct> wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__poll_t") int tomoyo_poll_log(Ptr<file> file,
      Ptr<poll_table_struct> wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__poll_t") int tomoyo_poll_query(Ptr<file> file,
      Ptr<poll_table_struct> wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static String tomoyo_print_bprm(Ptr<linux_binprm> bprm, Ptr<tomoyo_page_dump> dump) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_print_condition($arg1, (const struct tomoyo_condition*)$arg2)")
  public static boolean tomoyo_print_condition(Ptr<tomoyo_io_buffer> head,
      Ptr<tomoyo_condition> cond) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tomoyo_print_entry(Ptr<tomoyo_io_buffer> head, Ptr<tomoyo_acl_info> acl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static String tomoyo_print_header(Ptr<tomoyo_request_info> r) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_print_ip($arg1, (const unsigned int)$arg2, (const struct tomoyo_ipaddr_union*)$arg3)")
  public static void tomoyo_print_ip(String buf, @Unsigned int size, Ptr<tomoyo_ipaddr_union> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_print_ipv6($arg1, (const unsigned int)$arg2, (const struct in6_addr*)$arg3, (const struct in6_addr*)$arg4)")
  public static void tomoyo_print_ipv6(String buffer, @Unsigned int buffer_len,
      Ptr<in6_addr> min_ip, Ptr<in6_addr> max_ip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_print_name_union($arg1, (const struct tomoyo_name_union*)$arg2)")
  public static void tomoyo_print_name_union(Ptr<tomoyo_io_buffer> head,
      Ptr<tomoyo_name_union> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_print_number_union($arg1, (const struct tomoyo_number_union*)$arg2)")
  public static void tomoyo_print_number_union(Ptr<tomoyo_io_buffer> head,
      Ptr<tomoyo_number_union> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_print_number_union_nospace($arg1, (const struct tomoyo_number_union*)$arg2)")
  public static void tomoyo_print_number_union_nospace(Ptr<tomoyo_io_buffer> head,
      Ptr<tomoyo_number_union> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_print_ulong($arg1, (const int)$arg2, (const long unsigned int)$arg3, (const u8)$arg4)")
  public static void tomoyo_print_ulong(String buffer, int buffer_len, @Unsigned long value,
      char type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_put_name_union(Ptr<tomoyo_name_union> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_put_number_union(Ptr<tomoyo_number_union> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long tomoyo_read(Ptr<file> file, String buf,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_read_control($arg1, $arg2, (const int)$arg3)")
  public static @OriginalName("ssize_t") long tomoyo_read_control(Ptr<tomoyo_io_buffer> head,
      String buffer, int buffer_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_read_domain(Ptr<tomoyo_io_buffer> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_read_exception(Ptr<tomoyo_io_buffer> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_read_group($arg1, (const int)$arg2)")
  public static boolean tomoyo_read_group(Ptr<tomoyo_io_buffer> head, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_read_log(Ptr<tomoyo_io_buffer> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_read_manager(Ptr<tomoyo_io_buffer> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_read_pid(Ptr<tomoyo_io_buffer> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_read_profile(Ptr<tomoyo_io_buffer> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_read_query(Ptr<tomoyo_io_buffer> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long tomoyo_read_self(Ptr<file> file, String buf,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_read_stat(Ptr<tomoyo_io_buffer> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static String tomoyo_read_token(Ptr<tomoyo_acl_param> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_read_unlock(int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_read_version(Ptr<tomoyo_io_buffer> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_realpath_from_path((const struct path*)$arg1)")
  public static String tomoyo_realpath_from_path(Ptr<path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_realpath_nofollow((const u8*)$arg1)")
  public static String tomoyo_realpath_nofollow(String pathname) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_release(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_same_address_group((const struct tomoyo_acl_head*)$arg1, (const struct tomoyo_acl_head*)$arg2)")
  public static boolean tomoyo_same_address_group(Ptr<tomoyo_acl_head> a, Ptr<tomoyo_acl_head> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_same_aggregator((const struct tomoyo_acl_head*)$arg1, (const struct tomoyo_acl_head*)$arg2)")
  public static boolean tomoyo_same_aggregator(Ptr<tomoyo_acl_head> a, Ptr<tomoyo_acl_head> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_same_env_acl((const struct tomoyo_acl_info*)$arg1, (const struct tomoyo_acl_info*)$arg2)")
  public static boolean tomoyo_same_env_acl(Ptr<tomoyo_acl_info> a, Ptr<tomoyo_acl_info> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_same_inet_acl((const struct tomoyo_acl_info*)$arg1, (const struct tomoyo_acl_info*)$arg2)")
  public static boolean tomoyo_same_inet_acl(Ptr<tomoyo_acl_info> a, Ptr<tomoyo_acl_info> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_same_manager((const struct tomoyo_acl_head*)$arg1, (const struct tomoyo_acl_head*)$arg2)")
  public static boolean tomoyo_same_manager(Ptr<tomoyo_acl_head> a, Ptr<tomoyo_acl_head> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_same_mkdev_acl((const struct tomoyo_acl_info*)$arg1, (const struct tomoyo_acl_info*)$arg2)")
  public static boolean tomoyo_same_mkdev_acl(Ptr<tomoyo_acl_info> a, Ptr<tomoyo_acl_info> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_same_mount_acl((const struct tomoyo_acl_info*)$arg1, (const struct tomoyo_acl_info*)$arg2)")
  public static boolean tomoyo_same_mount_acl(Ptr<tomoyo_acl_info> a, Ptr<tomoyo_acl_info> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_same_number_group((const struct tomoyo_acl_head*)$arg1, (const struct tomoyo_acl_head*)$arg2)")
  public static boolean tomoyo_same_number_group(Ptr<tomoyo_acl_head> a, Ptr<tomoyo_acl_head> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_same_number_union((const struct tomoyo_number_union*)$arg1, (const struct tomoyo_number_union*)$arg2)")
  public static boolean tomoyo_same_number_union(Ptr<tomoyo_number_union> a,
      Ptr<tomoyo_number_union> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_same_path2_acl((const struct tomoyo_acl_info*)$arg1, (const struct tomoyo_acl_info*)$arg2)")
  public static boolean tomoyo_same_path2_acl(Ptr<tomoyo_acl_info> a, Ptr<tomoyo_acl_info> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_same_path_acl((const struct tomoyo_acl_info*)$arg1, (const struct tomoyo_acl_info*)$arg2)")
  public static boolean tomoyo_same_path_acl(Ptr<tomoyo_acl_info> a, Ptr<tomoyo_acl_info> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_same_path_group((const struct tomoyo_acl_head*)$arg1, (const struct tomoyo_acl_head*)$arg2)")
  public static boolean tomoyo_same_path_group(Ptr<tomoyo_acl_head> a, Ptr<tomoyo_acl_head> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_same_path_number_acl((const struct tomoyo_acl_info*)$arg1, (const struct tomoyo_acl_info*)$arg2)")
  public static boolean tomoyo_same_path_number_acl(Ptr<tomoyo_acl_info> a,
      Ptr<tomoyo_acl_info> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_same_task_acl((const struct tomoyo_acl_info*)$arg1, (const struct tomoyo_acl_info*)$arg2)")
  public static boolean tomoyo_same_task_acl(Ptr<tomoyo_acl_info> a, Ptr<tomoyo_acl_info> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_same_transition_control((const struct tomoyo_acl_head*)$arg1, (const struct tomoyo_acl_head*)$arg2)")
  public static boolean tomoyo_same_transition_control(Ptr<tomoyo_acl_head> a,
      Ptr<tomoyo_acl_head> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_same_unix_acl((const struct tomoyo_acl_info*)$arg1, (const struct tomoyo_acl_info*)$arg2)")
  public static boolean tomoyo_same_unix_acl(Ptr<tomoyo_acl_info> a, Ptr<tomoyo_acl_info> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_sb_mount((const u8*)$arg1, (const struct path*)$arg2, (const u8*)$arg3, $arg4, $arg5)")
  public static int tomoyo_sb_mount(String dev_name, Ptr<path> path, String type,
      @Unsigned long flags, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_sb_pivotroot((const struct path*)$arg1, (const struct path*)$arg2)")
  public static int tomoyo_sb_pivotroot(Ptr<path> old_path, Ptr<path> new_path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_sb_umount(Ptr<vfsmount> mnt, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_scan_bprm($arg1, (const short unsigned int)$arg2, (const struct tomoyo_argv*)$arg3, (const short unsigned int)$arg4, (const struct tomoyo_envp*)$arg5)")
  public static boolean tomoyo_scan_bprm(Ptr<tomoyo_execve> ee, @Unsigned short argc,
      Ptr<tomoyo_argv> argv, @Unsigned short envc, Ptr<tomoyo_envp> envp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_select_domain($arg1, (const u8*)$arg2)")
  public static boolean tomoyo_select_domain(Ptr<tomoyo_io_buffer> head, String data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_set_group($arg1, (const u8*)$arg2)")
  public static void tomoyo_set_group(Ptr<tomoyo_io_buffer> head, String category) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_set_mode($arg1, (const u8*)$arg2, $arg3)")
  public static int tomoyo_set_mode(String name, String value, Ptr<tomoyo_profile> profile) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_socket_bind(Ptr<socket> sock, Ptr<sockaddr> addr, int addr_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_socket_bind_permission(Ptr<socket> sock, Ptr<sockaddr> addr,
      int addr_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_socket_connect(Ptr<socket> sock, Ptr<sockaddr> addr, int addr_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_socket_connect_permission(Ptr<socket> sock, Ptr<sockaddr> addr,
      int addr_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_socket_listen(Ptr<socket> sock, int backlog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_socket_listen_permission(Ptr<socket> sock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_socket_sendmsg(Ptr<socket> sock, Ptr<msghdr> msg, int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_socket_sendmsg_permission(Ptr<socket> sock, Ptr<msghdr> msg, int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_str_starts($arg1, (const u8*)$arg2)")
  public static boolean tomoyo_str_starts(Ptr<String> src, String find) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_supervisor($arg1, (const u8*)$arg2, $arg3_)")
  public static int tomoyo_supervisor(Ptr<tomoyo_request_info> r, String fmt,
      java.lang.Object... param2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_task_alloc(Ptr<task_struct> task, @Unsigned long clone_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tomoyo_task_free(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_trigger_setup(String str) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_truncate(String str) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_try_to_gc((const enum tomoyo_policy_id)$arg1, $arg2)")
  public static void tomoyo_try_to_gc(tomoyo_policy_id type, Ptr<list_head> element) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_unix_entry((const struct tomoyo_addr_info*)$arg1)")
  public static int tomoyo_unix_entry(Ptr<tomoyo_addr_info> address) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_update_domain($arg1, (const int)$arg2, $arg3, (_Bool (*)(const struct tomoyo_acl_info*, const struct tomoyo_acl_info*))$arg4, (_Bool (*)(struct tomoyo_acl_info*, struct tomoyo_acl_info*, const _Bool))$arg5)")
  public static int tomoyo_update_domain(Ptr<tomoyo_acl_info> new_entry, int size,
      Ptr<tomoyo_acl_param> param, Ptr<?> check_duplicate, Ptr<?> merge_duplicate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_update_mkdev_acl((const u8)$arg1, $arg2)")
  public static int tomoyo_update_mkdev_acl(char perm, Ptr<tomoyo_acl_param> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_update_mount_acl(Ptr<tomoyo_acl_param> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_update_policy($arg1, (const int)$arg2, $arg3, (_Bool (*)(const struct tomoyo_acl_head*, const struct tomoyo_acl_head*))$arg4)")
  public static int tomoyo_update_policy(Ptr<tomoyo_acl_head> new_entry, int size,
      Ptr<tomoyo_acl_param> param, Ptr<?> check_duplicate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_update_stat((const u8)$arg1)")
  public static void tomoyo_update_stat(char index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_warn_oom((const u8*)$arg1)")
  public static void tomoyo_warn_oom(String function) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_write($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long tomoyo_write(Ptr<file> file, String buf,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_write_aggregator(Ptr<tomoyo_acl_param> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_write_answer(Ptr<tomoyo_io_buffer> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_write_control($arg1, (const u8*)$arg2, (const int)$arg3)")
  public static @OriginalName("ssize_t") long tomoyo_write_control(Ptr<tomoyo_io_buffer> head,
      String buffer, int buffer_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_write_domain(Ptr<tomoyo_io_buffer> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_write_domain2($arg1, $arg2, $arg3, (const _Bool)$arg4)")
  public static int tomoyo_write_domain2(Ptr<tomoyo_policy_namespace> ns, Ptr<list_head> list,
      String data, boolean is_delete) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_write_exception(Ptr<tomoyo_io_buffer> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_write_file(Ptr<tomoyo_acl_param> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_write_group($arg1, (const u8)$arg2)")
  public static int tomoyo_write_group(Ptr<tomoyo_acl_param> param, char type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_write_inet_network(Ptr<tomoyo_acl_param> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_write_log($arg1, (const u8*)$arg2, $arg3_)")
  public static void tomoyo_write_log(Ptr<tomoyo_request_info> r, String fmt,
      java.lang.Object... param2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_write_log2($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static void tomoyo_write_log2(Ptr<tomoyo_request_info> r, int len, String fmt,
      Ptr<__va_list_tag> args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_write_manager(Ptr<tomoyo_io_buffer> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_write_misc(Ptr<tomoyo_acl_param> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_write_pid(Ptr<tomoyo_io_buffer> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_write_profile(Ptr<tomoyo_io_buffer> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_write_self($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long tomoyo_write_self(Ptr<file> file, String buf,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_write_stat(Ptr<tomoyo_io_buffer> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_write_task(Ptr<tomoyo_acl_param> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tomoyo_write_transition_control($arg1, (const u8)$arg2)")
  public static int tomoyo_write_transition_control(Ptr<tomoyo_acl_param> param, char type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tomoyo_write_unix_network(Ptr<tomoyo_acl_param> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tomoyo_conditions_index"
  )
  public enum tomoyo_conditions_index implements Enum<tomoyo_conditions_index>, TypedEnum<tomoyo_conditions_index, java.lang. @Unsigned Integer> {
    /**
     * {@code TOMOYO_TASK_UID = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TOMOYO_TASK_UID"
    )
    TOMOYO_TASK_UID,

    /**
     * {@code TOMOYO_TASK_EUID = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TOMOYO_TASK_EUID"
    )
    TOMOYO_TASK_EUID,

    /**
     * {@code TOMOYO_TASK_SUID = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TOMOYO_TASK_SUID"
    )
    TOMOYO_TASK_SUID,

    /**
     * {@code TOMOYO_TASK_FSUID = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TOMOYO_TASK_FSUID"
    )
    TOMOYO_TASK_FSUID,

    /**
     * {@code TOMOYO_TASK_GID = 4}
     */
    @EnumMember(
        value = 4L,
        name = "TOMOYO_TASK_GID"
    )
    TOMOYO_TASK_GID,

    /**
     * {@code TOMOYO_TASK_EGID = 5}
     */
    @EnumMember(
        value = 5L,
        name = "TOMOYO_TASK_EGID"
    )
    TOMOYO_TASK_EGID,

    /**
     * {@code TOMOYO_TASK_SGID = 6}
     */
    @EnumMember(
        value = 6L,
        name = "TOMOYO_TASK_SGID"
    )
    TOMOYO_TASK_SGID,

    /**
     * {@code TOMOYO_TASK_FSGID = 7}
     */
    @EnumMember(
        value = 7L,
        name = "TOMOYO_TASK_FSGID"
    )
    TOMOYO_TASK_FSGID,

    /**
     * {@code TOMOYO_TASK_PID = 8}
     */
    @EnumMember(
        value = 8L,
        name = "TOMOYO_TASK_PID"
    )
    TOMOYO_TASK_PID,

    /**
     * {@code TOMOYO_TASK_PPID = 9}
     */
    @EnumMember(
        value = 9L,
        name = "TOMOYO_TASK_PPID"
    )
    TOMOYO_TASK_PPID,

    /**
     * {@code TOMOYO_EXEC_ARGC = 10}
     */
    @EnumMember(
        value = 10L,
        name = "TOMOYO_EXEC_ARGC"
    )
    TOMOYO_EXEC_ARGC,

    /**
     * {@code TOMOYO_EXEC_ENVC = 11}
     */
    @EnumMember(
        value = 11L,
        name = "TOMOYO_EXEC_ENVC"
    )
    TOMOYO_EXEC_ENVC,

    /**
     * {@code TOMOYO_TYPE_IS_SOCKET = 12}
     */
    @EnumMember(
        value = 12L,
        name = "TOMOYO_TYPE_IS_SOCKET"
    )
    TOMOYO_TYPE_IS_SOCKET,

    /**
     * {@code TOMOYO_TYPE_IS_SYMLINK = 13}
     */
    @EnumMember(
        value = 13L,
        name = "TOMOYO_TYPE_IS_SYMLINK"
    )
    TOMOYO_TYPE_IS_SYMLINK,

    /**
     * {@code TOMOYO_TYPE_IS_FILE = 14}
     */
    @EnumMember(
        value = 14L,
        name = "TOMOYO_TYPE_IS_FILE"
    )
    TOMOYO_TYPE_IS_FILE,

    /**
     * {@code TOMOYO_TYPE_IS_BLOCK_DEV = 15}
     */
    @EnumMember(
        value = 15L,
        name = "TOMOYO_TYPE_IS_BLOCK_DEV"
    )
    TOMOYO_TYPE_IS_BLOCK_DEV,

    /**
     * {@code TOMOYO_TYPE_IS_DIRECTORY = 16}
     */
    @EnumMember(
        value = 16L,
        name = "TOMOYO_TYPE_IS_DIRECTORY"
    )
    TOMOYO_TYPE_IS_DIRECTORY,

    /**
     * {@code TOMOYO_TYPE_IS_CHAR_DEV = 17}
     */
    @EnumMember(
        value = 17L,
        name = "TOMOYO_TYPE_IS_CHAR_DEV"
    )
    TOMOYO_TYPE_IS_CHAR_DEV,

    /**
     * {@code TOMOYO_TYPE_IS_FIFO = 18}
     */
    @EnumMember(
        value = 18L,
        name = "TOMOYO_TYPE_IS_FIFO"
    )
    TOMOYO_TYPE_IS_FIFO,

    /**
     * {@code TOMOYO_MODE_SETUID = 19}
     */
    @EnumMember(
        value = 19L,
        name = "TOMOYO_MODE_SETUID"
    )
    TOMOYO_MODE_SETUID,

    /**
     * {@code TOMOYO_MODE_SETGID = 20}
     */
    @EnumMember(
        value = 20L,
        name = "TOMOYO_MODE_SETGID"
    )
    TOMOYO_MODE_SETGID,

    /**
     * {@code TOMOYO_MODE_STICKY = 21}
     */
    @EnumMember(
        value = 21L,
        name = "TOMOYO_MODE_STICKY"
    )
    TOMOYO_MODE_STICKY,

    /**
     * {@code TOMOYO_MODE_OWNER_READ = 22}
     */
    @EnumMember(
        value = 22L,
        name = "TOMOYO_MODE_OWNER_READ"
    )
    TOMOYO_MODE_OWNER_READ,

    /**
     * {@code TOMOYO_MODE_OWNER_WRITE = 23}
     */
    @EnumMember(
        value = 23L,
        name = "TOMOYO_MODE_OWNER_WRITE"
    )
    TOMOYO_MODE_OWNER_WRITE,

    /**
     * {@code TOMOYO_MODE_OWNER_EXECUTE = 24}
     */
    @EnumMember(
        value = 24L,
        name = "TOMOYO_MODE_OWNER_EXECUTE"
    )
    TOMOYO_MODE_OWNER_EXECUTE,

    /**
     * {@code TOMOYO_MODE_GROUP_READ = 25}
     */
    @EnumMember(
        value = 25L,
        name = "TOMOYO_MODE_GROUP_READ"
    )
    TOMOYO_MODE_GROUP_READ,

    /**
     * {@code TOMOYO_MODE_GROUP_WRITE = 26}
     */
    @EnumMember(
        value = 26L,
        name = "TOMOYO_MODE_GROUP_WRITE"
    )
    TOMOYO_MODE_GROUP_WRITE,

    /**
     * {@code TOMOYO_MODE_GROUP_EXECUTE = 27}
     */
    @EnumMember(
        value = 27L,
        name = "TOMOYO_MODE_GROUP_EXECUTE"
    )
    TOMOYO_MODE_GROUP_EXECUTE,

    /**
     * {@code TOMOYO_MODE_OTHERS_READ = 28}
     */
    @EnumMember(
        value = 28L,
        name = "TOMOYO_MODE_OTHERS_READ"
    )
    TOMOYO_MODE_OTHERS_READ,

    /**
     * {@code TOMOYO_MODE_OTHERS_WRITE = 29}
     */
    @EnumMember(
        value = 29L,
        name = "TOMOYO_MODE_OTHERS_WRITE"
    )
    TOMOYO_MODE_OTHERS_WRITE,

    /**
     * {@code TOMOYO_MODE_OTHERS_EXECUTE = 30}
     */
    @EnumMember(
        value = 30L,
        name = "TOMOYO_MODE_OTHERS_EXECUTE"
    )
    TOMOYO_MODE_OTHERS_EXECUTE,

    /**
     * {@code TOMOYO_EXEC_REALPATH = 31}
     */
    @EnumMember(
        value = 31L,
        name = "TOMOYO_EXEC_REALPATH"
    )
    TOMOYO_EXEC_REALPATH,

    /**
     * {@code TOMOYO_SYMLINK_TARGET = 32}
     */
    @EnumMember(
        value = 32L,
        name = "TOMOYO_SYMLINK_TARGET"
    )
    TOMOYO_SYMLINK_TARGET,

    /**
     * {@code TOMOYO_PATH1_UID = 33}
     */
    @EnumMember(
        value = 33L,
        name = "TOMOYO_PATH1_UID"
    )
    TOMOYO_PATH1_UID,

    /**
     * {@code TOMOYO_PATH1_GID = 34}
     */
    @EnumMember(
        value = 34L,
        name = "TOMOYO_PATH1_GID"
    )
    TOMOYO_PATH1_GID,

    /**
     * {@code TOMOYO_PATH1_INO = 35}
     */
    @EnumMember(
        value = 35L,
        name = "TOMOYO_PATH1_INO"
    )
    TOMOYO_PATH1_INO,

    /**
     * {@code TOMOYO_PATH1_MAJOR = 36}
     */
    @EnumMember(
        value = 36L,
        name = "TOMOYO_PATH1_MAJOR"
    )
    TOMOYO_PATH1_MAJOR,

    /**
     * {@code TOMOYO_PATH1_MINOR = 37}
     */
    @EnumMember(
        value = 37L,
        name = "TOMOYO_PATH1_MINOR"
    )
    TOMOYO_PATH1_MINOR,

    /**
     * {@code TOMOYO_PATH1_PERM = 38}
     */
    @EnumMember(
        value = 38L,
        name = "TOMOYO_PATH1_PERM"
    )
    TOMOYO_PATH1_PERM,

    /**
     * {@code TOMOYO_PATH1_TYPE = 39}
     */
    @EnumMember(
        value = 39L,
        name = "TOMOYO_PATH1_TYPE"
    )
    TOMOYO_PATH1_TYPE,

    /**
     * {@code TOMOYO_PATH1_DEV_MAJOR = 40}
     */
    @EnumMember(
        value = 40L,
        name = "TOMOYO_PATH1_DEV_MAJOR"
    )
    TOMOYO_PATH1_DEV_MAJOR,

    /**
     * {@code TOMOYO_PATH1_DEV_MINOR = 41}
     */
    @EnumMember(
        value = 41L,
        name = "TOMOYO_PATH1_DEV_MINOR"
    )
    TOMOYO_PATH1_DEV_MINOR,

    /**
     * {@code TOMOYO_PATH2_UID = 42}
     */
    @EnumMember(
        value = 42L,
        name = "TOMOYO_PATH2_UID"
    )
    TOMOYO_PATH2_UID,

    /**
     * {@code TOMOYO_PATH2_GID = 43}
     */
    @EnumMember(
        value = 43L,
        name = "TOMOYO_PATH2_GID"
    )
    TOMOYO_PATH2_GID,

    /**
     * {@code TOMOYO_PATH2_INO = 44}
     */
    @EnumMember(
        value = 44L,
        name = "TOMOYO_PATH2_INO"
    )
    TOMOYO_PATH2_INO,

    /**
     * {@code TOMOYO_PATH2_MAJOR = 45}
     */
    @EnumMember(
        value = 45L,
        name = "TOMOYO_PATH2_MAJOR"
    )
    TOMOYO_PATH2_MAJOR,

    /**
     * {@code TOMOYO_PATH2_MINOR = 46}
     */
    @EnumMember(
        value = 46L,
        name = "TOMOYO_PATH2_MINOR"
    )
    TOMOYO_PATH2_MINOR,

    /**
     * {@code TOMOYO_PATH2_PERM = 47}
     */
    @EnumMember(
        value = 47L,
        name = "TOMOYO_PATH2_PERM"
    )
    TOMOYO_PATH2_PERM,

    /**
     * {@code TOMOYO_PATH2_TYPE = 48}
     */
    @EnumMember(
        value = 48L,
        name = "TOMOYO_PATH2_TYPE"
    )
    TOMOYO_PATH2_TYPE,

    /**
     * {@code TOMOYO_PATH2_DEV_MAJOR = 49}
     */
    @EnumMember(
        value = 49L,
        name = "TOMOYO_PATH2_DEV_MAJOR"
    )
    TOMOYO_PATH2_DEV_MAJOR,

    /**
     * {@code TOMOYO_PATH2_DEV_MINOR = 50}
     */
    @EnumMember(
        value = 50L,
        name = "TOMOYO_PATH2_DEV_MINOR"
    )
    TOMOYO_PATH2_DEV_MINOR,

    /**
     * {@code TOMOYO_PATH1_PARENT_UID = 51}
     */
    @EnumMember(
        value = 51L,
        name = "TOMOYO_PATH1_PARENT_UID"
    )
    TOMOYO_PATH1_PARENT_UID,

    /**
     * {@code TOMOYO_PATH1_PARENT_GID = 52}
     */
    @EnumMember(
        value = 52L,
        name = "TOMOYO_PATH1_PARENT_GID"
    )
    TOMOYO_PATH1_PARENT_GID,

    /**
     * {@code TOMOYO_PATH1_PARENT_INO = 53}
     */
    @EnumMember(
        value = 53L,
        name = "TOMOYO_PATH1_PARENT_INO"
    )
    TOMOYO_PATH1_PARENT_INO,

    /**
     * {@code TOMOYO_PATH1_PARENT_PERM = 54}
     */
    @EnumMember(
        value = 54L,
        name = "TOMOYO_PATH1_PARENT_PERM"
    )
    TOMOYO_PATH1_PARENT_PERM,

    /**
     * {@code TOMOYO_PATH2_PARENT_UID = 55}
     */
    @EnumMember(
        value = 55L,
        name = "TOMOYO_PATH2_PARENT_UID"
    )
    TOMOYO_PATH2_PARENT_UID,

    /**
     * {@code TOMOYO_PATH2_PARENT_GID = 56}
     */
    @EnumMember(
        value = 56L,
        name = "TOMOYO_PATH2_PARENT_GID"
    )
    TOMOYO_PATH2_PARENT_GID,

    /**
     * {@code TOMOYO_PATH2_PARENT_INO = 57}
     */
    @EnumMember(
        value = 57L,
        name = "TOMOYO_PATH2_PARENT_INO"
    )
    TOMOYO_PATH2_PARENT_INO,

    /**
     * {@code TOMOYO_PATH2_PARENT_PERM = 58}
     */
    @EnumMember(
        value = 58L,
        name = "TOMOYO_PATH2_PARENT_PERM"
    )
    TOMOYO_PATH2_PARENT_PERM,

    /**
     * {@code TOMOYO_MAX_CONDITION_KEYWORD = 59}
     */
    @EnumMember(
        value = 59L,
        name = "TOMOYO_MAX_CONDITION_KEYWORD"
    )
    TOMOYO_MAX_CONDITION_KEYWORD,

    /**
     * {@code TOMOYO_NUMBER_UNION = 60}
     */
    @EnumMember(
        value = 60L,
        name = "TOMOYO_NUMBER_UNION"
    )
    TOMOYO_NUMBER_UNION,

    /**
     * {@code TOMOYO_NAME_UNION = 61}
     */
    @EnumMember(
        value = 61L,
        name = "TOMOYO_NAME_UNION"
    )
    TOMOYO_NAME_UNION,

    /**
     * {@code TOMOYO_ARGV_ENTRY = 62}
     */
    @EnumMember(
        value = 62L,
        name = "TOMOYO_ARGV_ENTRY"
    )
    TOMOYO_ARGV_ENTRY,

    /**
     * {@code TOMOYO_ENVP_ENTRY = 63}
     */
    @EnumMember(
        value = 63L,
        name = "TOMOYO_ENVP_ENTRY"
    )
    TOMOYO_ENVP_ENTRY
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tomoyo_path_stat_index"
  )
  public enum tomoyo_path_stat_index implements Enum<tomoyo_path_stat_index>, TypedEnum<tomoyo_path_stat_index, java.lang. @Unsigned Integer> {
    /**
     * {@code TOMOYO_PATH1 = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TOMOYO_PATH1"
    )
    TOMOYO_PATH1,

    /**
     * {@code TOMOYO_PATH1_PARENT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TOMOYO_PATH1_PARENT"
    )
    TOMOYO_PATH1_PARENT,

    /**
     * {@code TOMOYO_PATH2 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TOMOYO_PATH2"
    )
    TOMOYO_PATH2,

    /**
     * {@code TOMOYO_PATH2_PARENT = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TOMOYO_PATH2_PARENT"
    )
    TOMOYO_PATH2_PARENT,

    /**
     * {@code TOMOYO_MAX_PATH_STAT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "TOMOYO_MAX_PATH_STAT"
    )
    TOMOYO_MAX_PATH_STAT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tomoyo_mode_index"
  )
  public enum tomoyo_mode_index implements Enum<tomoyo_mode_index>, TypedEnum<tomoyo_mode_index, java.lang. @Unsigned Integer> {
    /**
     * {@code TOMOYO_CONFIG_DISABLED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TOMOYO_CONFIG_DISABLED"
    )
    TOMOYO_CONFIG_DISABLED,

    /**
     * {@code TOMOYO_CONFIG_LEARNING = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TOMOYO_CONFIG_LEARNING"
    )
    TOMOYO_CONFIG_LEARNING,

    /**
     * {@code TOMOYO_CONFIG_PERMISSIVE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TOMOYO_CONFIG_PERMISSIVE"
    )
    TOMOYO_CONFIG_PERMISSIVE,

    /**
     * {@code TOMOYO_CONFIG_ENFORCING = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TOMOYO_CONFIG_ENFORCING"
    )
    TOMOYO_CONFIG_ENFORCING,

    /**
     * {@code TOMOYO_CONFIG_MAX_MODE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "TOMOYO_CONFIG_MAX_MODE"
    )
    TOMOYO_CONFIG_MAX_MODE,

    /**
     * {@code TOMOYO_CONFIG_WANT_REJECT_LOG = 64}
     */
    @EnumMember(
        value = 64L,
        name = "TOMOYO_CONFIG_WANT_REJECT_LOG"
    )
    TOMOYO_CONFIG_WANT_REJECT_LOG,

    /**
     * {@code TOMOYO_CONFIG_WANT_GRANT_LOG = 128}
     */
    @EnumMember(
        value = 128L,
        name = "TOMOYO_CONFIG_WANT_GRANT_LOG"
    )
    TOMOYO_CONFIG_WANT_GRANT_LOG,

    /**
     * {@code TOMOYO_CONFIG_USE_DEFAULT = 255}
     */
    @EnumMember(
        value = 255L,
        name = "TOMOYO_CONFIG_USE_DEFAULT"
    )
    TOMOYO_CONFIG_USE_DEFAULT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tomoyo_policy_id"
  )
  public enum tomoyo_policy_id implements Enum<tomoyo_policy_id>, TypedEnum<tomoyo_policy_id, java.lang. @Unsigned Integer> {
    /**
     * {@code TOMOYO_ID_GROUP = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TOMOYO_ID_GROUP"
    )
    TOMOYO_ID_GROUP,

    /**
     * {@code TOMOYO_ID_ADDRESS_GROUP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TOMOYO_ID_ADDRESS_GROUP"
    )
    TOMOYO_ID_ADDRESS_GROUP,

    /**
     * {@code TOMOYO_ID_PATH_GROUP = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TOMOYO_ID_PATH_GROUP"
    )
    TOMOYO_ID_PATH_GROUP,

    /**
     * {@code TOMOYO_ID_NUMBER_GROUP = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TOMOYO_ID_NUMBER_GROUP"
    )
    TOMOYO_ID_NUMBER_GROUP,

    /**
     * {@code TOMOYO_ID_TRANSITION_CONTROL = 4}
     */
    @EnumMember(
        value = 4L,
        name = "TOMOYO_ID_TRANSITION_CONTROL"
    )
    TOMOYO_ID_TRANSITION_CONTROL,

    /**
     * {@code TOMOYO_ID_AGGREGATOR = 5}
     */
    @EnumMember(
        value = 5L,
        name = "TOMOYO_ID_AGGREGATOR"
    )
    TOMOYO_ID_AGGREGATOR,

    /**
     * {@code TOMOYO_ID_MANAGER = 6}
     */
    @EnumMember(
        value = 6L,
        name = "TOMOYO_ID_MANAGER"
    )
    TOMOYO_ID_MANAGER,

    /**
     * {@code TOMOYO_ID_CONDITION = 7}
     */
    @EnumMember(
        value = 7L,
        name = "TOMOYO_ID_CONDITION"
    )
    TOMOYO_ID_CONDITION,

    /**
     * {@code TOMOYO_ID_NAME = 8}
     */
    @EnumMember(
        value = 8L,
        name = "TOMOYO_ID_NAME"
    )
    TOMOYO_ID_NAME,

    /**
     * {@code TOMOYO_ID_ACL = 9}
     */
    @EnumMember(
        value = 9L,
        name = "TOMOYO_ID_ACL"
    )
    TOMOYO_ID_ACL,

    /**
     * {@code TOMOYO_ID_DOMAIN = 10}
     */
    @EnumMember(
        value = 10L,
        name = "TOMOYO_ID_DOMAIN"
    )
    TOMOYO_ID_DOMAIN,

    /**
     * {@code TOMOYO_MAX_POLICY = 11}
     */
    @EnumMember(
        value = 11L,
        name = "TOMOYO_MAX_POLICY"
    )
    TOMOYO_MAX_POLICY
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tomoyo_domain_info_flags_index"
  )
  public enum tomoyo_domain_info_flags_index implements Enum<tomoyo_domain_info_flags_index>, TypedEnum<tomoyo_domain_info_flags_index, java.lang. @Unsigned Integer> {
    /**
     * {@code TOMOYO_DIF_QUOTA_WARNED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TOMOYO_DIF_QUOTA_WARNED"
    )
    TOMOYO_DIF_QUOTA_WARNED,

    /**
     * {@code TOMOYO_DIF_TRANSITION_FAILED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TOMOYO_DIF_TRANSITION_FAILED"
    )
    TOMOYO_DIF_TRANSITION_FAILED,

    /**
     * {@code TOMOYO_MAX_DOMAIN_INFO_FLAGS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TOMOYO_MAX_DOMAIN_INFO_FLAGS"
    )
    TOMOYO_MAX_DOMAIN_INFO_FLAGS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tomoyo_grant_log"
  )
  public enum tomoyo_grant_log implements Enum<tomoyo_grant_log>, TypedEnum<tomoyo_grant_log, java.lang. @Unsigned Integer> {
    /**
     * {@code TOMOYO_GRANTLOG_AUTO = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TOMOYO_GRANTLOG_AUTO"
    )
    TOMOYO_GRANTLOG_AUTO,

    /**
     * {@code TOMOYO_GRANTLOG_NO = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TOMOYO_GRANTLOG_NO"
    )
    TOMOYO_GRANTLOG_NO,

    /**
     * {@code TOMOYO_GRANTLOG_YES = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TOMOYO_GRANTLOG_YES"
    )
    TOMOYO_GRANTLOG_YES
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tomoyo_group_id"
  )
  public enum tomoyo_group_id implements Enum<tomoyo_group_id>, TypedEnum<tomoyo_group_id, java.lang. @Unsigned Integer> {
    /**
     * {@code TOMOYO_PATH_GROUP = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TOMOYO_PATH_GROUP"
    )
    TOMOYO_PATH_GROUP,

    /**
     * {@code TOMOYO_NUMBER_GROUP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TOMOYO_NUMBER_GROUP"
    )
    TOMOYO_NUMBER_GROUP,

    /**
     * {@code TOMOYO_ADDRESS_GROUP = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TOMOYO_ADDRESS_GROUP"
    )
    TOMOYO_ADDRESS_GROUP,

    /**
     * {@code TOMOYO_MAX_GROUP = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TOMOYO_MAX_GROUP"
    )
    TOMOYO_MAX_GROUP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tomoyo_path_acl_index"
  )
  public enum tomoyo_path_acl_index implements Enum<tomoyo_path_acl_index>, TypedEnum<tomoyo_path_acl_index, java.lang. @Unsigned Integer> {
    /**
     * {@code TOMOYO_TYPE_EXECUTE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TOMOYO_TYPE_EXECUTE"
    )
    TOMOYO_TYPE_EXECUTE,

    /**
     * {@code TOMOYO_TYPE_READ = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TOMOYO_TYPE_READ"
    )
    TOMOYO_TYPE_READ,

    /**
     * {@code TOMOYO_TYPE_WRITE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TOMOYO_TYPE_WRITE"
    )
    TOMOYO_TYPE_WRITE,

    /**
     * {@code TOMOYO_TYPE_APPEND = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TOMOYO_TYPE_APPEND"
    )
    TOMOYO_TYPE_APPEND,

    /**
     * {@code TOMOYO_TYPE_UNLINK = 4}
     */
    @EnumMember(
        value = 4L,
        name = "TOMOYO_TYPE_UNLINK"
    )
    TOMOYO_TYPE_UNLINK,

    /**
     * {@code TOMOYO_TYPE_GETATTR = 5}
     */
    @EnumMember(
        value = 5L,
        name = "TOMOYO_TYPE_GETATTR"
    )
    TOMOYO_TYPE_GETATTR,

    /**
     * {@code TOMOYO_TYPE_RMDIR = 6}
     */
    @EnumMember(
        value = 6L,
        name = "TOMOYO_TYPE_RMDIR"
    )
    TOMOYO_TYPE_RMDIR,

    /**
     * {@code TOMOYO_TYPE_TRUNCATE = 7}
     */
    @EnumMember(
        value = 7L,
        name = "TOMOYO_TYPE_TRUNCATE"
    )
    TOMOYO_TYPE_TRUNCATE,

    /**
     * {@code TOMOYO_TYPE_SYMLINK = 8}
     */
    @EnumMember(
        value = 8L,
        name = "TOMOYO_TYPE_SYMLINK"
    )
    TOMOYO_TYPE_SYMLINK,

    /**
     * {@code TOMOYO_TYPE_CHROOT = 9}
     */
    @EnumMember(
        value = 9L,
        name = "TOMOYO_TYPE_CHROOT"
    )
    TOMOYO_TYPE_CHROOT,

    /**
     * {@code TOMOYO_TYPE_UMOUNT = 10}
     */
    @EnumMember(
        value = 10L,
        name = "TOMOYO_TYPE_UMOUNT"
    )
    TOMOYO_TYPE_UMOUNT,

    /**
     * {@code TOMOYO_MAX_PATH_OPERATION = 11}
     */
    @EnumMember(
        value = 11L,
        name = "TOMOYO_MAX_PATH_OPERATION"
    )
    TOMOYO_MAX_PATH_OPERATION
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tomoyo_memory_stat_type"
  )
  public enum tomoyo_memory_stat_type implements Enum<tomoyo_memory_stat_type>, TypedEnum<tomoyo_memory_stat_type, java.lang. @Unsigned Integer> {
    /**
     * {@code TOMOYO_MEMORY_POLICY = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TOMOYO_MEMORY_POLICY"
    )
    TOMOYO_MEMORY_POLICY,

    /**
     * {@code TOMOYO_MEMORY_AUDIT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TOMOYO_MEMORY_AUDIT"
    )
    TOMOYO_MEMORY_AUDIT,

    /**
     * {@code TOMOYO_MEMORY_QUERY = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TOMOYO_MEMORY_QUERY"
    )
    TOMOYO_MEMORY_QUERY,

    /**
     * {@code TOMOYO_MAX_MEMORY_STAT = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TOMOYO_MAX_MEMORY_STAT"
    )
    TOMOYO_MAX_MEMORY_STAT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tomoyo_mkdev_acl_index"
  )
  public enum tomoyo_mkdev_acl_index implements Enum<tomoyo_mkdev_acl_index>, TypedEnum<tomoyo_mkdev_acl_index, java.lang. @Unsigned Integer> {
    /**
     * {@code TOMOYO_TYPE_MKBLOCK = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TOMOYO_TYPE_MKBLOCK"
    )
    TOMOYO_TYPE_MKBLOCK,

    /**
     * {@code TOMOYO_TYPE_MKCHAR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TOMOYO_TYPE_MKCHAR"
    )
    TOMOYO_TYPE_MKCHAR,

    /**
     * {@code TOMOYO_MAX_MKDEV_OPERATION = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TOMOYO_MAX_MKDEV_OPERATION"
    )
    TOMOYO_MAX_MKDEV_OPERATION
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tomoyo_network_acl_index"
  )
  public enum tomoyo_network_acl_index implements Enum<tomoyo_network_acl_index>, TypedEnum<tomoyo_network_acl_index, java.lang. @Unsigned Integer> {
    /**
     * {@code TOMOYO_NETWORK_BIND = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TOMOYO_NETWORK_BIND"
    )
    TOMOYO_NETWORK_BIND,

    /**
     * {@code TOMOYO_NETWORK_LISTEN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TOMOYO_NETWORK_LISTEN"
    )
    TOMOYO_NETWORK_LISTEN,

    /**
     * {@code TOMOYO_NETWORK_CONNECT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TOMOYO_NETWORK_CONNECT"
    )
    TOMOYO_NETWORK_CONNECT,

    /**
     * {@code TOMOYO_NETWORK_SEND = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TOMOYO_NETWORK_SEND"
    )
    TOMOYO_NETWORK_SEND,

    /**
     * {@code TOMOYO_MAX_NETWORK_OPERATION = 4}
     */
    @EnumMember(
        value = 4L,
        name = "TOMOYO_MAX_NETWORK_OPERATION"
    )
    TOMOYO_MAX_NETWORK_OPERATION
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tomoyo_path2_acl_index"
  )
  public enum tomoyo_path2_acl_index implements Enum<tomoyo_path2_acl_index>, TypedEnum<tomoyo_path2_acl_index, java.lang. @Unsigned Integer> {
    /**
     * {@code TOMOYO_TYPE_LINK = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TOMOYO_TYPE_LINK"
    )
    TOMOYO_TYPE_LINK,

    /**
     * {@code TOMOYO_TYPE_RENAME = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TOMOYO_TYPE_RENAME"
    )
    TOMOYO_TYPE_RENAME,

    /**
     * {@code TOMOYO_TYPE_PIVOT_ROOT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TOMOYO_TYPE_PIVOT_ROOT"
    )
    TOMOYO_TYPE_PIVOT_ROOT,

    /**
     * {@code TOMOYO_MAX_PATH2_OPERATION = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TOMOYO_MAX_PATH2_OPERATION"
    )
    TOMOYO_MAX_PATH2_OPERATION
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tomoyo_path_number_acl_index"
  )
  public enum tomoyo_path_number_acl_index implements Enum<tomoyo_path_number_acl_index>, TypedEnum<tomoyo_path_number_acl_index, java.lang. @Unsigned Integer> {
    /**
     * {@code TOMOYO_TYPE_CREATE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TOMOYO_TYPE_CREATE"
    )
    TOMOYO_TYPE_CREATE,

    /**
     * {@code TOMOYO_TYPE_MKDIR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TOMOYO_TYPE_MKDIR"
    )
    TOMOYO_TYPE_MKDIR,

    /**
     * {@code TOMOYO_TYPE_MKFIFO = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TOMOYO_TYPE_MKFIFO"
    )
    TOMOYO_TYPE_MKFIFO,

    /**
     * {@code TOMOYO_TYPE_MKSOCK = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TOMOYO_TYPE_MKSOCK"
    )
    TOMOYO_TYPE_MKSOCK,

    /**
     * {@code TOMOYO_TYPE_IOCTL = 4}
     */
    @EnumMember(
        value = 4L,
        name = "TOMOYO_TYPE_IOCTL"
    )
    TOMOYO_TYPE_IOCTL,

    /**
     * {@code TOMOYO_TYPE_CHMOD = 5}
     */
    @EnumMember(
        value = 5L,
        name = "TOMOYO_TYPE_CHMOD"
    )
    TOMOYO_TYPE_CHMOD,

    /**
     * {@code TOMOYO_TYPE_CHOWN = 6}
     */
    @EnumMember(
        value = 6L,
        name = "TOMOYO_TYPE_CHOWN"
    )
    TOMOYO_TYPE_CHOWN,

    /**
     * {@code TOMOYO_TYPE_CHGRP = 7}
     */
    @EnumMember(
        value = 7L,
        name = "TOMOYO_TYPE_CHGRP"
    )
    TOMOYO_TYPE_CHGRP,

    /**
     * {@code TOMOYO_MAX_PATH_NUMBER_OPERATION = 8}
     */
    @EnumMember(
        value = 8L,
        name = "TOMOYO_MAX_PATH_NUMBER_OPERATION"
    )
    TOMOYO_MAX_PATH_NUMBER_OPERATION
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tomoyo_securityfs_interface_index"
  )
  public enum tomoyo_securityfs_interface_index implements Enum<tomoyo_securityfs_interface_index>, TypedEnum<tomoyo_securityfs_interface_index, java.lang. @Unsigned Integer> {
    /**
     * {@code TOMOYO_DOMAINPOLICY = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TOMOYO_DOMAINPOLICY"
    )
    TOMOYO_DOMAINPOLICY,

    /**
     * {@code TOMOYO_EXCEPTIONPOLICY = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TOMOYO_EXCEPTIONPOLICY"
    )
    TOMOYO_EXCEPTIONPOLICY,

    /**
     * {@code TOMOYO_PROCESS_STATUS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TOMOYO_PROCESS_STATUS"
    )
    TOMOYO_PROCESS_STATUS,

    /**
     * {@code TOMOYO_STAT = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TOMOYO_STAT"
    )
    TOMOYO_STAT,

    /**
     * {@code TOMOYO_AUDIT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "TOMOYO_AUDIT"
    )
    TOMOYO_AUDIT,

    /**
     * {@code TOMOYO_VERSION = 5}
     */
    @EnumMember(
        value = 5L,
        name = "TOMOYO_VERSION"
    )
    TOMOYO_VERSION,

    /**
     * {@code TOMOYO_PROFILE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "TOMOYO_PROFILE"
    )
    TOMOYO_PROFILE,

    /**
     * {@code TOMOYO_QUERY = 7}
     */
    @EnumMember(
        value = 7L,
        name = "TOMOYO_QUERY"
    )
    TOMOYO_QUERY,

    /**
     * {@code TOMOYO_MANAGER = 8}
     */
    @EnumMember(
        value = 8L,
        name = "TOMOYO_MANAGER"
    )
    TOMOYO_MANAGER
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tomoyo_mac_index"
  )
  public enum tomoyo_mac_index implements Enum<tomoyo_mac_index>, TypedEnum<tomoyo_mac_index, java.lang. @Unsigned Integer> {
    /**
     * {@code TOMOYO_MAC_FILE_EXECUTE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TOMOYO_MAC_FILE_EXECUTE"
    )
    TOMOYO_MAC_FILE_EXECUTE,

    /**
     * {@code TOMOYO_MAC_FILE_OPEN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TOMOYO_MAC_FILE_OPEN"
    )
    TOMOYO_MAC_FILE_OPEN,

    /**
     * {@code TOMOYO_MAC_FILE_CREATE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TOMOYO_MAC_FILE_CREATE"
    )
    TOMOYO_MAC_FILE_CREATE,

    /**
     * {@code TOMOYO_MAC_FILE_UNLINK = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TOMOYO_MAC_FILE_UNLINK"
    )
    TOMOYO_MAC_FILE_UNLINK,

    /**
     * {@code TOMOYO_MAC_FILE_GETATTR = 4}
     */
    @EnumMember(
        value = 4L,
        name = "TOMOYO_MAC_FILE_GETATTR"
    )
    TOMOYO_MAC_FILE_GETATTR,

    /**
     * {@code TOMOYO_MAC_FILE_MKDIR = 5}
     */
    @EnumMember(
        value = 5L,
        name = "TOMOYO_MAC_FILE_MKDIR"
    )
    TOMOYO_MAC_FILE_MKDIR,

    /**
     * {@code TOMOYO_MAC_FILE_RMDIR = 6}
     */
    @EnumMember(
        value = 6L,
        name = "TOMOYO_MAC_FILE_RMDIR"
    )
    TOMOYO_MAC_FILE_RMDIR,

    /**
     * {@code TOMOYO_MAC_FILE_MKFIFO = 7}
     */
    @EnumMember(
        value = 7L,
        name = "TOMOYO_MAC_FILE_MKFIFO"
    )
    TOMOYO_MAC_FILE_MKFIFO,

    /**
     * {@code TOMOYO_MAC_FILE_MKSOCK = 8}
     */
    @EnumMember(
        value = 8L,
        name = "TOMOYO_MAC_FILE_MKSOCK"
    )
    TOMOYO_MAC_FILE_MKSOCK,

    /**
     * {@code TOMOYO_MAC_FILE_TRUNCATE = 9}
     */
    @EnumMember(
        value = 9L,
        name = "TOMOYO_MAC_FILE_TRUNCATE"
    )
    TOMOYO_MAC_FILE_TRUNCATE,

    /**
     * {@code TOMOYO_MAC_FILE_SYMLINK = 10}
     */
    @EnumMember(
        value = 10L,
        name = "TOMOYO_MAC_FILE_SYMLINK"
    )
    TOMOYO_MAC_FILE_SYMLINK,

    /**
     * {@code TOMOYO_MAC_FILE_MKBLOCK = 11}
     */
    @EnumMember(
        value = 11L,
        name = "TOMOYO_MAC_FILE_MKBLOCK"
    )
    TOMOYO_MAC_FILE_MKBLOCK,

    /**
     * {@code TOMOYO_MAC_FILE_MKCHAR = 12}
     */
    @EnumMember(
        value = 12L,
        name = "TOMOYO_MAC_FILE_MKCHAR"
    )
    TOMOYO_MAC_FILE_MKCHAR,

    /**
     * {@code TOMOYO_MAC_FILE_LINK = 13}
     */
    @EnumMember(
        value = 13L,
        name = "TOMOYO_MAC_FILE_LINK"
    )
    TOMOYO_MAC_FILE_LINK,

    /**
     * {@code TOMOYO_MAC_FILE_RENAME = 14}
     */
    @EnumMember(
        value = 14L,
        name = "TOMOYO_MAC_FILE_RENAME"
    )
    TOMOYO_MAC_FILE_RENAME,

    /**
     * {@code TOMOYO_MAC_FILE_CHMOD = 15}
     */
    @EnumMember(
        value = 15L,
        name = "TOMOYO_MAC_FILE_CHMOD"
    )
    TOMOYO_MAC_FILE_CHMOD,

    /**
     * {@code TOMOYO_MAC_FILE_CHOWN = 16}
     */
    @EnumMember(
        value = 16L,
        name = "TOMOYO_MAC_FILE_CHOWN"
    )
    TOMOYO_MAC_FILE_CHOWN,

    /**
     * {@code TOMOYO_MAC_FILE_CHGRP = 17}
     */
    @EnumMember(
        value = 17L,
        name = "TOMOYO_MAC_FILE_CHGRP"
    )
    TOMOYO_MAC_FILE_CHGRP,

    /**
     * {@code TOMOYO_MAC_FILE_IOCTL = 18}
     */
    @EnumMember(
        value = 18L,
        name = "TOMOYO_MAC_FILE_IOCTL"
    )
    TOMOYO_MAC_FILE_IOCTL,

    /**
     * {@code TOMOYO_MAC_FILE_CHROOT = 19}
     */
    @EnumMember(
        value = 19L,
        name = "TOMOYO_MAC_FILE_CHROOT"
    )
    TOMOYO_MAC_FILE_CHROOT,

    /**
     * {@code TOMOYO_MAC_FILE_MOUNT = 20}
     */
    @EnumMember(
        value = 20L,
        name = "TOMOYO_MAC_FILE_MOUNT"
    )
    TOMOYO_MAC_FILE_MOUNT,

    /**
     * {@code TOMOYO_MAC_FILE_UMOUNT = 21}
     */
    @EnumMember(
        value = 21L,
        name = "TOMOYO_MAC_FILE_UMOUNT"
    )
    TOMOYO_MAC_FILE_UMOUNT,

    /**
     * {@code TOMOYO_MAC_FILE_PIVOT_ROOT = 22}
     */
    @EnumMember(
        value = 22L,
        name = "TOMOYO_MAC_FILE_PIVOT_ROOT"
    )
    TOMOYO_MAC_FILE_PIVOT_ROOT,

    /**
     * {@code TOMOYO_MAC_NETWORK_INET_STREAM_BIND = 23}
     */
    @EnumMember(
        value = 23L,
        name = "TOMOYO_MAC_NETWORK_INET_STREAM_BIND"
    )
    TOMOYO_MAC_NETWORK_INET_STREAM_BIND,

    /**
     * {@code TOMOYO_MAC_NETWORK_INET_STREAM_LISTEN = 24}
     */
    @EnumMember(
        value = 24L,
        name = "TOMOYO_MAC_NETWORK_INET_STREAM_LISTEN"
    )
    TOMOYO_MAC_NETWORK_INET_STREAM_LISTEN,

    /**
     * {@code TOMOYO_MAC_NETWORK_INET_STREAM_CONNECT = 25}
     */
    @EnumMember(
        value = 25L,
        name = "TOMOYO_MAC_NETWORK_INET_STREAM_CONNECT"
    )
    TOMOYO_MAC_NETWORK_INET_STREAM_CONNECT,

    /**
     * {@code TOMOYO_MAC_NETWORK_INET_DGRAM_BIND = 26}
     */
    @EnumMember(
        value = 26L,
        name = "TOMOYO_MAC_NETWORK_INET_DGRAM_BIND"
    )
    TOMOYO_MAC_NETWORK_INET_DGRAM_BIND,

    /**
     * {@code TOMOYO_MAC_NETWORK_INET_DGRAM_SEND = 27}
     */
    @EnumMember(
        value = 27L,
        name = "TOMOYO_MAC_NETWORK_INET_DGRAM_SEND"
    )
    TOMOYO_MAC_NETWORK_INET_DGRAM_SEND,

    /**
     * {@code TOMOYO_MAC_NETWORK_INET_RAW_BIND = 28}
     */
    @EnumMember(
        value = 28L,
        name = "TOMOYO_MAC_NETWORK_INET_RAW_BIND"
    )
    TOMOYO_MAC_NETWORK_INET_RAW_BIND,

    /**
     * {@code TOMOYO_MAC_NETWORK_INET_RAW_SEND = 29}
     */
    @EnumMember(
        value = 29L,
        name = "TOMOYO_MAC_NETWORK_INET_RAW_SEND"
    )
    TOMOYO_MAC_NETWORK_INET_RAW_SEND,

    /**
     * {@code TOMOYO_MAC_NETWORK_UNIX_STREAM_BIND = 30}
     */
    @EnumMember(
        value = 30L,
        name = "TOMOYO_MAC_NETWORK_UNIX_STREAM_BIND"
    )
    TOMOYO_MAC_NETWORK_UNIX_STREAM_BIND,

    /**
     * {@code TOMOYO_MAC_NETWORK_UNIX_STREAM_LISTEN = 31}
     */
    @EnumMember(
        value = 31L,
        name = "TOMOYO_MAC_NETWORK_UNIX_STREAM_LISTEN"
    )
    TOMOYO_MAC_NETWORK_UNIX_STREAM_LISTEN,

    /**
     * {@code TOMOYO_MAC_NETWORK_UNIX_STREAM_CONNECT = 32}
     */
    @EnumMember(
        value = 32L,
        name = "TOMOYO_MAC_NETWORK_UNIX_STREAM_CONNECT"
    )
    TOMOYO_MAC_NETWORK_UNIX_STREAM_CONNECT,

    /**
     * {@code TOMOYO_MAC_NETWORK_UNIX_DGRAM_BIND = 33}
     */
    @EnumMember(
        value = 33L,
        name = "TOMOYO_MAC_NETWORK_UNIX_DGRAM_BIND"
    )
    TOMOYO_MAC_NETWORK_UNIX_DGRAM_BIND,

    /**
     * {@code TOMOYO_MAC_NETWORK_UNIX_DGRAM_SEND = 34}
     */
    @EnumMember(
        value = 34L,
        name = "TOMOYO_MAC_NETWORK_UNIX_DGRAM_SEND"
    )
    TOMOYO_MAC_NETWORK_UNIX_DGRAM_SEND,

    /**
     * {@code TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_BIND = 35}
     */
    @EnumMember(
        value = 35L,
        name = "TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_BIND"
    )
    TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_BIND,

    /**
     * {@code TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_LISTEN = 36}
     */
    @EnumMember(
        value = 36L,
        name = "TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_LISTEN"
    )
    TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_LISTEN,

    /**
     * {@code TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_CONNECT = 37}
     */
    @EnumMember(
        value = 37L,
        name = "TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_CONNECT"
    )
    TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_CONNECT,

    /**
     * {@code TOMOYO_MAC_ENVIRON = 38}
     */
    @EnumMember(
        value = 38L,
        name = "TOMOYO_MAC_ENVIRON"
    )
    TOMOYO_MAC_ENVIRON,

    /**
     * {@code TOMOYO_MAX_MAC_INDEX = 39}
     */
    @EnumMember(
        value = 39L,
        name = "TOMOYO_MAX_MAC_INDEX"
    )
    TOMOYO_MAX_MAC_INDEX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tomoyo_mac_category_index"
  )
  public enum tomoyo_mac_category_index implements Enum<tomoyo_mac_category_index>, TypedEnum<tomoyo_mac_category_index, java.lang. @Unsigned Integer> {
    /**
     * {@code TOMOYO_MAC_CATEGORY_FILE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TOMOYO_MAC_CATEGORY_FILE"
    )
    TOMOYO_MAC_CATEGORY_FILE,

    /**
     * {@code TOMOYO_MAC_CATEGORY_NETWORK = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TOMOYO_MAC_CATEGORY_NETWORK"
    )
    TOMOYO_MAC_CATEGORY_NETWORK,

    /**
     * {@code TOMOYO_MAC_CATEGORY_MISC = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TOMOYO_MAC_CATEGORY_MISC"
    )
    TOMOYO_MAC_CATEGORY_MISC,

    /**
     * {@code TOMOYO_MAX_MAC_CATEGORY_INDEX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TOMOYO_MAX_MAC_CATEGORY_INDEX"
    )
    TOMOYO_MAX_MAC_CATEGORY_INDEX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tomoyo_pref_index"
  )
  public enum tomoyo_pref_index implements Enum<tomoyo_pref_index>, TypedEnum<tomoyo_pref_index, java.lang. @Unsigned Integer> {
    /**
     * {@code TOMOYO_PREF_MAX_AUDIT_LOG = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TOMOYO_PREF_MAX_AUDIT_LOG"
    )
    TOMOYO_PREF_MAX_AUDIT_LOG,

    /**
     * {@code TOMOYO_PREF_MAX_LEARNING_ENTRY = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TOMOYO_PREF_MAX_LEARNING_ENTRY"
    )
    TOMOYO_PREF_MAX_LEARNING_ENTRY,

    /**
     * {@code TOMOYO_MAX_PREF = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TOMOYO_MAX_PREF"
    )
    TOMOYO_MAX_PREF
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_shared_acl_head"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_shared_acl_head extends Struct {
    public list_head list;

    public atomic_t users;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_path_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_path_info extends Struct {
    public String name;

    public @Unsigned int hash;

    public @Unsigned short const_len;

    public boolean is_dir;

    public boolean is_patterned;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_request_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_request_info extends Struct {
    public Ptr<tomoyo_obj_info> obj;

    public Ptr<tomoyo_execve> ee;

    public Ptr<tomoyo_domain_info> domain;

    public param_of_tomoyo_request_info param;

    public Ptr<tomoyo_acl_info> matched_acl;

    public char param_type;

    public boolean granted;

    public char retry;

    public char profile;

    public char mode;

    public char type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_obj_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_obj_info extends Struct {
    public boolean validate_done;

    public boolean @Size(4) [] stat_valid;

    public path path1;

    public path path2;

    public tomoyo_mini_stat @Size(4) [] stat;

    public Ptr<tomoyo_path_info> symlink_target;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_execve"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_execve extends Struct {
    public tomoyo_request_info r;

    public tomoyo_obj_info obj;

    public Ptr<linux_binprm> bprm;

    public Ptr<tomoyo_path_info> transition;

    public tomoyo_page_dump dump;

    public String tmp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_domain_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_domain_info extends Struct {
    public list_head list;

    public list_head acl_info_list;

    public Ptr<tomoyo_path_info> domainname;

    public Ptr<tomoyo_policy_namespace> ns;

    public @Unsigned long @Size(4) [] group;

    public char profile;

    public boolean is_deleted;

    public boolean @Size(2) [] flags;

    public atomic_t users;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_acl_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_acl_info extends Struct {
    public list_head list;

    public Ptr<tomoyo_condition> cond;

    public @OriginalName("s8") byte is_deleted;

    public char type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_mini_stat"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_mini_stat extends Struct {
    public kuid_t uid;

    public kgid_t gid;

    public @Unsigned @OriginalName("ino_t") long ino;

    public @Unsigned @OriginalName("umode_t") short mode;

    public @Unsigned @OriginalName("dev_t") int dev;

    public @Unsigned @OriginalName("dev_t") int rdev;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_page_dump"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_page_dump extends Struct {
    public Ptr<page> page;

    public String data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_condition"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_condition extends Struct {
    public tomoyo_shared_acl_head head;

    public @Unsigned int size;

    public @Unsigned short condc;

    public @Unsigned short numbers_count;

    public @Unsigned short names_count;

    public @Unsigned short argc;

    public @Unsigned short envc;

    public char grant_log;

    public Ptr<tomoyo_path_info> transit;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_policy_namespace"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_policy_namespace extends Struct {
    public Ptr<tomoyo_profile> @Size(256) [] profile_ptr;

    public list_head @Size(3) [] group_list;

    public list_head @Size(11) [] policy_list;

    public list_head @Size(256) [] acl_group;

    public list_head namespace_list;

    public @Unsigned int profile_version;

    public String name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_io_buffer"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_io_buffer extends Struct {
    public Ptr<?> read;

    public Ptr<?> write;

    public Ptr<?> poll;

    public mutex io_sem;

    public String read_user_buf;

    public @Unsigned long read_user_buf_avail;

    public r_of_tomoyo_io_buffer r;

    public w_of_tomoyo_io_buffer w;

    public String read_buf;

    public @Unsigned long readbuf_size;

    public String write_buf;

    public @Unsigned long writebuf_size;

    public tomoyo_securityfs_interface_index type;

    public char users;

    public list_head list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_preference"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_preference extends Struct {
    public @Unsigned int learning_max_entry;

    public boolean enforcing_verbose;

    public boolean learning_verbose;

    public boolean permissive_verbose;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_profile"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_profile extends Struct {
    public Ptr<tomoyo_path_info> comment;

    public Ptr<tomoyo_preference> learning;

    public Ptr<tomoyo_preference> permissive;

    public Ptr<tomoyo_preference> enforcing;

    public tomoyo_preference preference;

    public char default_config;

    public char @Size(42) [] config;

    public @Unsigned int @Size(2) [] pref;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_time"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_time extends Struct {
    public @Unsigned short year;

    public char month;

    public char day;

    public char hour;

    public char min;

    public char sec;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_log"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_log extends Struct {
    public list_head list;

    public String log;

    public int size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tomoyo_value_type"
  )
  public enum tomoyo_value_type implements Enum<tomoyo_value_type>, TypedEnum<tomoyo_value_type, java.lang. @Unsigned Integer> {
    /**
     * {@code TOMOYO_VALUE_TYPE_INVALID = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TOMOYO_VALUE_TYPE_INVALID"
    )
    TOMOYO_VALUE_TYPE_INVALID,

    /**
     * {@code TOMOYO_VALUE_TYPE_DECIMAL = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TOMOYO_VALUE_TYPE_DECIMAL"
    )
    TOMOYO_VALUE_TYPE_DECIMAL,

    /**
     * {@code TOMOYO_VALUE_TYPE_OCTAL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TOMOYO_VALUE_TYPE_OCTAL"
    )
    TOMOYO_VALUE_TYPE_OCTAL,

    /**
     * {@code TOMOYO_VALUE_TYPE_HEXADECIMAL = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TOMOYO_VALUE_TYPE_HEXADECIMAL"
    )
    TOMOYO_VALUE_TYPE_HEXADECIMAL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tomoyo_transition_type"
  )
  public enum tomoyo_transition_type implements Enum<tomoyo_transition_type>, TypedEnum<tomoyo_transition_type, java.lang. @Unsigned Integer> {
    /**
     * {@code TOMOYO_TRANSITION_CONTROL_NO_RESET = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TOMOYO_TRANSITION_CONTROL_NO_RESET"
    )
    TOMOYO_TRANSITION_CONTROL_NO_RESET,

    /**
     * {@code TOMOYO_TRANSITION_CONTROL_RESET = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TOMOYO_TRANSITION_CONTROL_RESET"
    )
    TOMOYO_TRANSITION_CONTROL_RESET,

    /**
     * {@code TOMOYO_TRANSITION_CONTROL_NO_INITIALIZE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TOMOYO_TRANSITION_CONTROL_NO_INITIALIZE"
    )
    TOMOYO_TRANSITION_CONTROL_NO_INITIALIZE,

    /**
     * {@code TOMOYO_TRANSITION_CONTROL_INITIALIZE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TOMOYO_TRANSITION_CONTROL_INITIALIZE"
    )
    TOMOYO_TRANSITION_CONTROL_INITIALIZE,

    /**
     * {@code TOMOYO_TRANSITION_CONTROL_NO_KEEP = 4}
     */
    @EnumMember(
        value = 4L,
        name = "TOMOYO_TRANSITION_CONTROL_NO_KEEP"
    )
    TOMOYO_TRANSITION_CONTROL_NO_KEEP,

    /**
     * {@code TOMOYO_TRANSITION_CONTROL_KEEP = 5}
     */
    @EnumMember(
        value = 5L,
        name = "TOMOYO_TRANSITION_CONTROL_KEEP"
    )
    TOMOYO_TRANSITION_CONTROL_KEEP,

    /**
     * {@code TOMOYO_MAX_TRANSITION_TYPE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "TOMOYO_MAX_TRANSITION_TYPE"
    )
    TOMOYO_MAX_TRANSITION_TYPE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tomoyo_acl_entry_type_index"
  )
  public enum tomoyo_acl_entry_type_index implements Enum<tomoyo_acl_entry_type_index>, TypedEnum<tomoyo_acl_entry_type_index, java.lang. @Unsigned Integer> {
    /**
     * {@code TOMOYO_TYPE_PATH_ACL = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TOMOYO_TYPE_PATH_ACL"
    )
    TOMOYO_TYPE_PATH_ACL,

    /**
     * {@code TOMOYO_TYPE_PATH2_ACL = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TOMOYO_TYPE_PATH2_ACL"
    )
    TOMOYO_TYPE_PATH2_ACL,

    /**
     * {@code TOMOYO_TYPE_PATH_NUMBER_ACL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TOMOYO_TYPE_PATH_NUMBER_ACL"
    )
    TOMOYO_TYPE_PATH_NUMBER_ACL,

    /**
     * {@code TOMOYO_TYPE_MKDEV_ACL = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TOMOYO_TYPE_MKDEV_ACL"
    )
    TOMOYO_TYPE_MKDEV_ACL,

    /**
     * {@code TOMOYO_TYPE_MOUNT_ACL = 4}
     */
    @EnumMember(
        value = 4L,
        name = "TOMOYO_TYPE_MOUNT_ACL"
    )
    TOMOYO_TYPE_MOUNT_ACL,

    /**
     * {@code TOMOYO_TYPE_INET_ACL = 5}
     */
    @EnumMember(
        value = 5L,
        name = "TOMOYO_TYPE_INET_ACL"
    )
    TOMOYO_TYPE_INET_ACL,

    /**
     * {@code TOMOYO_TYPE_UNIX_ACL = 6}
     */
    @EnumMember(
        value = 6L,
        name = "TOMOYO_TYPE_UNIX_ACL"
    )
    TOMOYO_TYPE_UNIX_ACL,

    /**
     * {@code TOMOYO_TYPE_ENV_ACL = 7}
     */
    @EnumMember(
        value = 7L,
        name = "TOMOYO_TYPE_ENV_ACL"
    )
    TOMOYO_TYPE_ENV_ACL,

    /**
     * {@code TOMOYO_TYPE_MANUAL_TASK_ACL = 8}
     */
    @EnumMember(
        value = 8L,
        name = "TOMOYO_TYPE_MANUAL_TASK_ACL"
    )
    TOMOYO_TYPE_MANUAL_TASK_ACL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tomoyo_policy_stat_type"
  )
  public enum tomoyo_policy_stat_type implements Enum<tomoyo_policy_stat_type>, TypedEnum<tomoyo_policy_stat_type, java.lang. @Unsigned Integer> {
    /**
     * {@code TOMOYO_STAT_POLICY_UPDATES = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TOMOYO_STAT_POLICY_UPDATES"
    )
    TOMOYO_STAT_POLICY_UPDATES,

    /**
     * {@code TOMOYO_STAT_POLICY_LEARNING = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TOMOYO_STAT_POLICY_LEARNING"
    )
    TOMOYO_STAT_POLICY_LEARNING,

    /**
     * {@code TOMOYO_STAT_POLICY_PERMISSIVE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TOMOYO_STAT_POLICY_PERMISSIVE"
    )
    TOMOYO_STAT_POLICY_PERMISSIVE,

    /**
     * {@code TOMOYO_STAT_POLICY_ENFORCING = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TOMOYO_STAT_POLICY_ENFORCING"
    )
    TOMOYO_STAT_POLICY_ENFORCING,

    /**
     * {@code TOMOYO_MAX_POLICY_STAT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "TOMOYO_MAX_POLICY_STAT"
    )
    TOMOYO_MAX_POLICY_STAT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_acl_head"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_acl_head extends Struct {
    public list_head list;

    public @OriginalName("s8") byte is_deleted;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_name"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_name extends Struct {
    public tomoyo_shared_acl_head head;

    public tomoyo_path_info entry;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_name_union"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_name_union extends Struct {
    public Ptr<tomoyo_path_info> filename;

    public Ptr<tomoyo_group> group;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_group"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_group extends Struct {
    public tomoyo_shared_acl_head head;

    public Ptr<tomoyo_path_info> group_name;

    public list_head member_list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_number_union"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_number_union extends Struct {
    public @Unsigned long @Size(2) [] values;

    public Ptr<tomoyo_group> group;

    public char @Size(2) [] value_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_ipaddr_union"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_ipaddr_union extends Struct {
    public in6_addr @Size(2) [] ip;

    public Ptr<tomoyo_group> group;

    public boolean is_ipv6;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_path_group"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_path_group extends Struct {
    public tomoyo_acl_head head;

    public Ptr<tomoyo_path_info> member_name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_number_group"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_number_group extends Struct {
    public tomoyo_acl_head head;

    public tomoyo_number_union number;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_address_group"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_address_group extends Struct {
    public tomoyo_acl_head head;

    public tomoyo_ipaddr_union address;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_argv"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_argv extends Struct {
    public @Unsigned long index;

    public Ptr<tomoyo_path_info> value;

    public boolean is_not;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_envp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_envp extends Struct {
    public Ptr<tomoyo_path_info> name;

    public Ptr<tomoyo_path_info> value;

    public boolean is_not;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_condition_element"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_condition_element extends Struct {
    public char left;

    public char right;

    public boolean equals;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_task_acl"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_task_acl extends Struct {
    public tomoyo_acl_info head;

    public Ptr<tomoyo_path_info> domainname;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_path_acl"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_path_acl extends Struct {
    public tomoyo_acl_info head;

    public @Unsigned short perm;

    public tomoyo_name_union name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_path_number_acl"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_path_number_acl extends Struct {
    public tomoyo_acl_info head;

    public char perm;

    public tomoyo_name_union name;

    public tomoyo_number_union number;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_mkdev_acl"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_mkdev_acl extends Struct {
    public tomoyo_acl_info head;

    public char perm;

    public tomoyo_name_union name;

    public tomoyo_number_union mode;

    public tomoyo_number_union major;

    public tomoyo_number_union minor;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_path2_acl"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_path2_acl extends Struct {
    public tomoyo_acl_info head;

    public char perm;

    public tomoyo_name_union name1;

    public tomoyo_name_union name2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_mount_acl"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_mount_acl extends Struct {
    public tomoyo_acl_info head;

    public tomoyo_name_union dev_name;

    public tomoyo_name_union dir_name;

    public tomoyo_name_union fs_type;

    public tomoyo_number_union flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_env_acl"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_env_acl extends Struct {
    public tomoyo_acl_info head;

    public Ptr<tomoyo_path_info> env;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_inet_acl"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_inet_acl extends Struct {
    public tomoyo_acl_info head;

    public char protocol;

    public char perm;

    public tomoyo_ipaddr_union address;

    public tomoyo_number_union port;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_unix_acl"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_unix_acl extends Struct {
    public tomoyo_acl_info head;

    public char protocol;

    public char perm;

    public tomoyo_name_union name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_acl_param"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_acl_param extends Struct {
    public String data;

    public Ptr<list_head> list;

    public Ptr<tomoyo_policy_namespace> ns;

    public boolean is_delete;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_transition_control"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_transition_control extends Struct {
    public tomoyo_acl_head head;

    public char type;

    public boolean is_last_name;

    public Ptr<tomoyo_path_info> domainname;

    public Ptr<tomoyo_path_info> program;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_aggregator"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_aggregator extends Struct {
    public tomoyo_acl_head head;

    public Ptr<tomoyo_path_info> original_name;

    public Ptr<tomoyo_path_info> aggregated_name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_manager"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_manager extends Struct {
    public tomoyo_acl_head head;

    public Ptr<tomoyo_path_info> manager;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_task"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_task extends Struct {
    public Ptr<tomoyo_domain_info> domain_info;

    public Ptr<tomoyo_domain_info> old_domain_info;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_query"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_query extends Struct {
    public list_head list;

    public Ptr<tomoyo_domain_info> domain;

    public String query;

    public @Unsigned long query_len;

    public @Unsigned int serial;

    public char timer;

    public char answer;

    public char retry;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tomoyo_special_mount"
  )
  public enum tomoyo_special_mount implements Enum<tomoyo_special_mount>, TypedEnum<tomoyo_special_mount, java.lang. @Unsigned Integer> {
    /**
     * {@code TOMOYO_MOUNT_BIND = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TOMOYO_MOUNT_BIND"
    )
    TOMOYO_MOUNT_BIND,

    /**
     * {@code TOMOYO_MOUNT_MOVE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TOMOYO_MOUNT_MOVE"
    )
    TOMOYO_MOUNT_MOVE,

    /**
     * {@code TOMOYO_MOUNT_REMOUNT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TOMOYO_MOUNT_REMOUNT"
    )
    TOMOYO_MOUNT_REMOUNT,

    /**
     * {@code TOMOYO_MOUNT_MAKE_UNBINDABLE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TOMOYO_MOUNT_MAKE_UNBINDABLE"
    )
    TOMOYO_MOUNT_MAKE_UNBINDABLE,

    /**
     * {@code TOMOYO_MOUNT_MAKE_PRIVATE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "TOMOYO_MOUNT_MAKE_PRIVATE"
    )
    TOMOYO_MOUNT_MAKE_PRIVATE,

    /**
     * {@code TOMOYO_MOUNT_MAKE_SLAVE = 5}
     */
    @EnumMember(
        value = 5L,
        name = "TOMOYO_MOUNT_MAKE_SLAVE"
    )
    TOMOYO_MOUNT_MAKE_SLAVE,

    /**
     * {@code TOMOYO_MOUNT_MAKE_SHARED = 6}
     */
    @EnumMember(
        value = 6L,
        name = "TOMOYO_MOUNT_MAKE_SHARED"
    )
    TOMOYO_MOUNT_MAKE_SHARED,

    /**
     * {@code TOMOYO_MAX_SPECIAL_MOUNT = 7}
     */
    @EnumMember(
        value = 7L,
        name = "TOMOYO_MAX_SPECIAL_MOUNT"
    )
    TOMOYO_MAX_SPECIAL_MOUNT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_inet_addr_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_inet_addr_info extends Struct {
    public @Unsigned @OriginalName("__be16") short port;

    public Ptr<java.lang. @Unsigned @OriginalName("__be32") Integer> address;

    public boolean is_ipv6;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_unix_addr_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_unix_addr_info extends Struct {
    public Ptr<java.lang.Character> addr;

    public @Unsigned int addr_len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tomoyo_addr_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tomoyo_addr_info extends Struct {
    public char protocol;

    public char operation;

    public tomoyo_inet_addr_info inet;

    public tomoyo_unix_addr_info unix0;
  }
}
