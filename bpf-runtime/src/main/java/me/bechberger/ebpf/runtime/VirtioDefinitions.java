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
 * Generated class for BPF runtime types that start with virtio
 */
@java.lang.SuppressWarnings("unused")
public final class VirtioDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __virtio_config_changed(Ptr<virtio_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __virtio_unbreak_device(Ptr<virtio_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_add_status(Ptr<virtio_device> dev, @Unsigned int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_balloon_driver_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_balloon_driver_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_balloon_oom_notify(Ptr<notifier_block> nb, @Unsigned long dummy,
      Ptr<?> parm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_balloon_report_free_page(Ptr<virtio_balloon> vb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long virtio_balloon_shrinker_count(Ptr<shrinker> shrinker,
      Ptr<shrink_control> sc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long virtio_balloon_shrinker_scan(Ptr<shrinker> shrinker,
      Ptr<shrink_control> sc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_blk_fini() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_blk_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_break_device(Ptr<virtio_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("virtio_check_driver_offered_feature((const struct virtio_device*)$arg1, $arg2)")
  public static void virtio_check_driver_offered_feature(Ptr<virtio_device> vdev,
      @Unsigned int fbit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_commit_rqs(Ptr<blk_mq_hw_ctx> hctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_config_changed(Ptr<virtio_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_config_driver_disable(Ptr<virtio_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_config_driver_enable(Ptr<virtio_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_console_fini() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_console_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("virtio_dev_match($arg1, (const struct device_driver*)$arg2)")
  public static int virtio_dev_match(Ptr<device> _dv, Ptr<device_driver> _dr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_dev_probe(Ptr<device> _d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_dev_remove(Ptr<device> _d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_dev_shutdown(Ptr<device> _d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_device_freeze(Ptr<virtio_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_device_reset_done(Ptr<virtio_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_device_reset_prepare(Ptr<virtio_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_device_restore(Ptr<virtio_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_device_restore_priv(Ptr<virtio_device> dev, boolean restore) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("virtio_features_copy($arg1, (const long long unsigned int*)$arg2)")
  public static void virtio_features_copy(Ptr<java.lang. @Unsigned Long> to,
      Ptr<java.lang. @Unsigned Long> from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_features_ok(Ptr<virtio_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("virtio_features_test_bit((const long long unsigned int*)$arg1, $arg2)")
  public static boolean virtio_features_test_bit(Ptr<java.lang. @Unsigned Long> features,
      @Unsigned int bit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_iommu_drv_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_iommu_drv_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct cpumask*)virtio_irq_get_affinity($arg1, $arg2))")
  public static Ptr<cpumask> virtio_irq_get_affinity(Ptr<device> _d, @Unsigned int irq_vec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("virtio_max_dma_size((const struct virtio_device*)$arg1)")
  public static @Unsigned long virtio_max_dma_size(Ptr<virtio_device> vdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_mmio_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_mmio_freeze(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_mmio_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_mmio_probe(Ptr<platform_device> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_mmio_release_dev(Ptr<device> _d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_mmio_remove(Ptr<platform_device> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_mmio_restore(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_net_driver_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_net_driver_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("virtio_net_hdr_tnl_to_skb($arg1, (const struct virtio_net_hdr_v1_hash_tunnel*)$arg2, $arg3, $arg4, $arg5)")
  public static int virtio_net_hdr_tnl_to_skb(Ptr<sk_buff> skb,
      Ptr<virtio_net_hdr_v1_hash_tunnel> vhdr, boolean tnl_hdr_negotiated,
      boolean tnl_csum_negotiated, boolean little_endian) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean virtio_no_restricted_mem_acc(Ptr<virtio_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_pci_admin_cmd_cap_init(Ptr<virtio_device> virtio_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_pci_admin_cmd_dev_parts_objects_enable(Ptr<virtio_device> virtio_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_pci_admin_cmd_list_init(Ptr<virtio_device> virtio_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_pci_admin_dev_parts_get(Ptr<pci_dev> pdev, @Unsigned short obj_type,
      @Unsigned int id, char get_type, Ptr<scatterlist> res_sg,
      Ptr<java.lang. @Unsigned Integer> res_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_pci_admin_dev_parts_metadata_get(Ptr<pci_dev> pdev,
      @Unsigned short obj_type, @Unsigned int id, char metadata_type,
      Ptr<java.lang. @Unsigned Integer> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_pci_admin_dev_parts_set(Ptr<pci_dev> pdev, Ptr<scatterlist> data_sg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean virtio_pci_admin_has_dev_parts(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean virtio_pci_admin_has_legacy_io(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_pci_admin_legacy_common_io_read(Ptr<pci_dev> pdev, char offset,
      char size, Ptr<java.lang.Character> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_pci_admin_legacy_common_io_write(Ptr<pci_dev> pdev, char offset,
      char size, Ptr<java.lang.Character> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_pci_admin_legacy_device_io_read(Ptr<pci_dev> pdev, char offset,
      char size, Ptr<java.lang.Character> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_pci_admin_legacy_device_io_write(Ptr<pci_dev> pdev, char offset,
      char size, Ptr<java.lang.Character> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_pci_admin_legacy_io_notify_info(Ptr<pci_dev> pdev, char req_bar_flags,
      Ptr<java.lang.Character> bar, Ptr<java.lang. @Unsigned Long> bar_offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_pci_admin_legacy_io_read(Ptr<pci_dev> pdev, @Unsigned short opcode,
      char offset, char size, Ptr<java.lang.Character> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_pci_admin_legacy_io_write(Ptr<pci_dev> pdev, @Unsigned short opcode,
      char offset, char size, Ptr<java.lang.Character> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_pci_admin_mode_set(Ptr<pci_dev> pdev, char flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_pci_admin_obj_create(Ptr<pci_dev> pdev, @Unsigned short obj_type,
      char operation_type, Ptr<java.lang. @Unsigned Integer> obj_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_pci_admin_obj_destroy(Ptr<pci_dev> pdev, @Unsigned short obj_type,
      @Unsigned int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_pci_driver_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_pci_driver_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_pci_find_shm_cap(Ptr<pci_dev> dev, char required_id,
      Ptr<java.lang.Character> bar, Ptr<java.lang. @Unsigned Long> offset,
      Ptr<java.lang. @Unsigned Long> len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_pci_freeze(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_pci_legacy_probe(Ptr<virtio_pci_device> vp_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_pci_legacy_remove(Ptr<virtio_pci_device> vp_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_pci_modern_probe(Ptr<virtio_pci_device> vp_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_pci_modern_remove(Ptr<virtio_pci_device> vp_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("virtio_pci_probe($arg1, (const struct pci_device_id*)$arg2)")
  public static int virtio_pci_probe(Ptr<pci_dev> pci_dev, Ptr<pci_device_id> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_pci_release_dev(Ptr<device> _d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_pci_remove(Ptr<pci_dev> pci_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_pci_reset_done(Ptr<pci_dev> pci_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_pci_reset_prepare(Ptr<pci_dev> pci_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_pci_restore(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_pci_resume(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_pci_sriov_configure(Ptr<pci_dev> pci_dev, int num_vfs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_pci_suspend(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<virtio_device> virtio_pci_vf_get_pf_dev(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("virtio_queue_rq($arg1, (const struct blk_mq_queue_data*)$arg2)")
  public static @OriginalName("blk_status_t") char virtio_queue_rq(Ptr<blk_mq_hw_ctx> hctx,
      Ptr<blk_mq_queue_data> bd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_queue_rqs(Ptr<rq_list> rqlist) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean virtio_require_restricted_mem_acc(Ptr<virtio_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_reset_device(Ptr<virtio_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void virtio_scsi_fini() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int virtio_scsi_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("virtio_uevent((const struct device*)$arg1, $arg2)")
  public static int virtio_uevent(Ptr<device> _dv, Ptr<kobj_uevent_env> env) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_device_id"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_device_id extends Struct {
    public @Unsigned int device;

    public @Unsigned int vendor;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_device"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_device extends Struct {
    public int index;

    public boolean failed;

    public boolean config_core_enabled;

    public boolean config_driver_disabled;

    public boolean config_change_pending;

    public @OriginalName("spinlock_t") spinlock config_lock;

    public @OriginalName("spinlock_t") spinlock vqs_list_lock;

    public device dev;

    public virtio_device_id id;

    public Ptr<virtio_config_ops> config;

    public @OriginalName("vringh_config_ops") Ptr<?> vringh_config;

    public list_head vqs;

    @InlineUnion(41095)
    public @Unsigned long features;

    @InlineUnion(41095)
    public @Unsigned long @Size(2) [] features_array;

    public Ptr<?> priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_config_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_config_ops extends Struct {
    public Ptr<?> get;

    public Ptr<?> set;

    public Ptr<?> generation;

    public Ptr<?> get_status;

    public Ptr<?> set_status;

    public Ptr<?> reset;

    public Ptr<?> find_vqs;

    public Ptr<?> del_vqs;

    public Ptr<?> synchronize_cbs;

    public Ptr<?> get_features;

    public Ptr<?> get_extended_features;

    public Ptr<?> finalize_features;

    public Ptr<?> bus_name;

    public Ptr<?> set_vq_affinity;

    public Ptr<?> get_vq_affinity;

    public Ptr<?> get_shm_region;

    public Ptr<?> disable_vq_and_reset;

    public Ptr<?> enable_vq_after_reset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_driver"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_driver extends Struct {
    public device_driver driver;

    public Ptr<virtio_device_id> id_table;

    public Ptr<java.lang. @Unsigned Integer> feature_table;

    public @Unsigned int feature_table_size;

    public Ptr<java.lang. @Unsigned Integer> feature_table_legacy;

    public @Unsigned int feature_table_size_legacy;

    public Ptr<?> validate;

    public Ptr<?> probe;

    public Ptr<?> scan;

    public Ptr<?> remove;

    public Ptr<?> config_changed;

    public Ptr<?> freeze;

    public Ptr<?> restore;

    public Ptr<?> reset_prepare;

    public Ptr<?> reset_done;

    public Ptr<?> shutdown;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_shm_region"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_shm_region extends Struct {
    public @Unsigned long addr;

    public @Unsigned long len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_pci_common_cfg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_pci_common_cfg extends Struct {
    public @Unsigned @OriginalName("__le32") int device_feature_select;

    public @Unsigned @OriginalName("__le32") int device_feature;

    public @Unsigned @OriginalName("__le32") int guest_feature_select;

    public @Unsigned @OriginalName("__le32") int guest_feature;

    public @Unsigned @OriginalName("__le16") short msix_config;

    public @Unsigned @OriginalName("__le16") short num_queues;

    public char device_status;

    public char config_generation;

    public @Unsigned @OriginalName("__le16") short queue_select;

    public @Unsigned @OriginalName("__le16") short queue_size;

    public @Unsigned @OriginalName("__le16") short queue_msix_vector;

    public @Unsigned @OriginalName("__le16") short queue_enable;

    public @Unsigned @OriginalName("__le16") short queue_notify_off;

    public @Unsigned @OriginalName("__le32") int queue_desc_lo;

    public @Unsigned @OriginalName("__le32") int queue_desc_hi;

    public @Unsigned @OriginalName("__le32") int queue_avail_lo;

    public @Unsigned @OriginalName("__le32") int queue_avail_hi;

    public @Unsigned @OriginalName("__le32") int queue_used_lo;

    public @Unsigned @OriginalName("__le32") int queue_used_hi;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_pci_modern_common_cfg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_pci_modern_common_cfg extends Struct {
    public virtio_pci_common_cfg cfg;

    public @Unsigned @OriginalName("__le16") short queue_notify_data;

    public @Unsigned @OriginalName("__le16") short queue_reset;

    public @Unsigned @OriginalName("__le16") short admin_queue_index;

    public @Unsigned @OriginalName("__le16") short admin_queue_num;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_pci_modern_device"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_pci_modern_device extends Struct {
    public Ptr<pci_dev> pci_dev;

    public Ptr<virtio_pci_common_cfg> common;

    public Ptr<?> device;

    public Ptr<?> notify_base;

    public @Unsigned @OriginalName("resource_size_t") long notify_pa;

    public Ptr<java.lang.Character> isr;

    public @Unsigned long notify_len;

    public @Unsigned long device_len;

    public @Unsigned long common_len;

    public int notify_map_cap;

    public @Unsigned int notify_offset_multiplier;

    public int modern_bars;

    public virtio_device_id id;

    public Ptr<?> device_id_check;

    public @Unsigned long dma_mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_pci_legacy_device"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_pci_legacy_device extends Struct {
    public Ptr<pci_dev> pci_dev;

    public Ptr<java.lang.Character> isr;

    public Ptr<?> ioaddr;

    public virtio_device_id id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_mmio_device"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_mmio_device extends Struct {
    public virtio_device vdev;

    public Ptr<platform_device> pdev;

    public Ptr<?> base;

    public @Unsigned long version;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_admin_cmd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_admin_cmd extends Struct {
    public @Unsigned @OriginalName("__le16") short opcode;

    public @Unsigned @OriginalName("__le16") short group_type;

    public @Unsigned @OriginalName("__le64") long group_member_id;

    public Ptr<scatterlist> data_sg;

    public Ptr<scatterlist> result_sg;

    public completion completion;

    public @Unsigned int result_sg_size;

    public int ret;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_admin_cmd_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_admin_cmd_hdr extends Struct {
    public @Unsigned @OriginalName("__le16") short opcode;

    public @Unsigned @OriginalName("__le16") short group_type;

    public char @Size(12) [] reserved1;

    public @Unsigned @OriginalName("__le64") long group_member_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_admin_cmd_status"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_admin_cmd_status extends Struct {
    public @Unsigned @OriginalName("__le16") short status;

    public @Unsigned @OriginalName("__le16") short status_qualifier;

    public char @Size(4) [] reserved2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_dev_parts_cap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_dev_parts_cap extends Struct {
    public char get_parts_resource_objects_limit;

    public char set_parts_resource_objects_limit;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_admin_cmd_query_cap_id_result"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_admin_cmd_query_cap_id_result extends Struct {
    public @Unsigned @OriginalName("__le64") long @Size(1) [] supported_caps;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_admin_cmd_cap_get_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_admin_cmd_cap_get_data extends Struct {
    public @Unsigned @OriginalName("__le16") short id;

    public char @Size(6) [] reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_admin_cmd_cap_set_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_admin_cmd_cap_set_data extends Struct {
    public @Unsigned @OriginalName("__le16") short id;

    public char @Size(6) [] reserved;

    public char @Size(0) [] cap_specific_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_admin_cmd_resource_obj_cmd_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_admin_cmd_resource_obj_cmd_hdr extends Struct {
    public @Unsigned @OriginalName("__le16") short type;

    public char @Size(2) [] reserved;

    public @Unsigned @OriginalName("__le32") int id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_admin_cmd_resource_obj_create_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_admin_cmd_resource_obj_create_data extends Struct {
    public virtio_admin_cmd_resource_obj_cmd_hdr hdr;

    public @Unsigned @OriginalName("__le64") long flags;

    public char @Size(0) [] resource_obj_specific_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_resource_obj_dev_parts"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_resource_obj_dev_parts extends Struct {
    public char type;

    public char @Size(7) [] reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_admin_cmd_dev_parts_metadata_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_admin_cmd_dev_parts_metadata_data extends Struct {
    public virtio_admin_cmd_resource_obj_cmd_hdr hdr;

    public char type;

    public char @Size(7) [] reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_dev_part_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_dev_part_hdr extends Struct {
    public @Unsigned @OriginalName("__le16") short part_type;

    public char flags;

    public char reserved;

    public selector_of_virtio_dev_part_hdr selector;

    public @Unsigned @OriginalName("__le32") int length;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_admin_cmd_dev_parts_metadata_result"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_admin_cmd_dev_parts_metadata_result extends Struct {
    @InlineUnion(41341)
    public parts_size_of_anon_member_of_virtio_admin_cmd_dev_parts_metadata_result parts_size;

    @InlineUnion(41341)
    public hdr_list_count_of_anon_member_of_virtio_admin_cmd_dev_parts_metadata_result hdr_list_count;

    @InlineUnion(41341)
    public hdr_list_of_anon_member_of_virtio_admin_cmd_dev_parts_metadata_result hdr_list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_admin_cmd_dev_parts_get_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_admin_cmd_dev_parts_get_data extends Struct {
    public virtio_admin_cmd_resource_obj_cmd_hdr hdr;

    public char type;

    public char @Size(7) [] reserved;

    public virtio_dev_part_hdr @Size(0) [] hdr_list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_admin_cmd_dev_mode_set_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_admin_cmd_dev_mode_set_data extends Struct {
    public char flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_pci_vq_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_pci_vq_info extends Struct {
    public Ptr<virtqueue> vq;

    public list_head node;

    public @Unsigned int msix_vector;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_pci_admin_vq"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_pci_admin_vq extends Struct {
    public Ptr<virtio_pci_vq_info> info;

    public @OriginalName("spinlock_t") spinlock lock;

    public @Unsigned long supported_cmds;

    public @Unsigned long supported_caps;

    public char max_dev_parts_objects;

    public ida dev_parts_ida;

    public char @Size(10) [] name;

    public @Unsigned short vq_index;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_pci_device"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_pci_device extends Struct {
    public virtio_device vdev;

    public Ptr<pci_dev> pci_dev;

    @InlineUnion(41348)
    public virtio_pci_legacy_device ldev;

    @InlineUnion(41348)
    public virtio_pci_modern_device mdev;

    public boolean is_legacy;

    public Ptr<java.lang.Character> isr;

    public @OriginalName("spinlock_t") spinlock lock;

    public list_head virtqueues;

    public list_head slow_virtqueues;

    public Ptr<Ptr<virtio_pci_vq_info>> vqs;

    public virtio_pci_admin_vq admin_vq;

    public int msix_enabled;

    public int intx_enabled;

    public Ptr<@OriginalName("cpumask_var_t") Ptr<cpumask>> msix_affinity_masks;

    public Ptr<char @Size(256) []> msix_names;

    public @Unsigned int msix_vectors;

    public @Unsigned int msix_used_vectors;

    public boolean per_vq_vectors;

    public Ptr<?> setup_vq;

    public Ptr<?> del_vq;

    public Ptr<?> config_vector;

    public Ptr<?> avq_index;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_admin_cmd_legacy_wr_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_admin_cmd_legacy_wr_data extends Struct {
    public char offset;

    public char @Size(7) [] reserved;

    public char @Size(0) [] registers;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_admin_cmd_legacy_rd_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_admin_cmd_legacy_rd_data extends Struct {
    public char offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_admin_cmd_notify_info_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_admin_cmd_notify_info_data extends Struct {
    public char flags;

    public char bar;

    public char @Size(6) [] padding;

    public @Unsigned @OriginalName("__le64") long offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_admin_cmd_notify_info_result"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_admin_cmd_notify_info_result extends Struct {
    public virtio_admin_cmd_notify_info_data @Size(4) [] entries;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_balloon_config"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_balloon_config extends Struct {
    public @Unsigned @OriginalName("__le32") int num_pages;

    public @Unsigned @OriginalName("__le32") int actual;

    @InlineUnion(41403)
    public @Unsigned @OriginalName("__le32") int free_page_hint_cmd_id;

    @InlineUnion(41403)
    public @Unsigned @OriginalName("__le32") int free_page_report_cmd_id;

    public @Unsigned @OriginalName("__le32") int poison_val;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_balloon_stat"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_balloon_stat extends Struct {
    public @Unsigned @OriginalName("__virtio16") short tag;

    public @Unsigned @OriginalName("__virtio64") long val;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum virtio_balloon_vq"
  )
  public enum virtio_balloon_vq implements Enum<virtio_balloon_vq>, TypedEnum<virtio_balloon_vq, java.lang. @Unsigned Integer> {
    /**
     * {@code VIRTIO_BALLOON_VQ_INFLATE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "VIRTIO_BALLOON_VQ_INFLATE"
    )
    VIRTIO_BALLOON_VQ_INFLATE,

    /**
     * {@code VIRTIO_BALLOON_VQ_DEFLATE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "VIRTIO_BALLOON_VQ_DEFLATE"
    )
    VIRTIO_BALLOON_VQ_DEFLATE,

    /**
     * {@code VIRTIO_BALLOON_VQ_STATS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "VIRTIO_BALLOON_VQ_STATS"
    )
    VIRTIO_BALLOON_VQ_STATS,

    /**
     * {@code VIRTIO_BALLOON_VQ_FREE_PAGE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "VIRTIO_BALLOON_VQ_FREE_PAGE"
    )
    VIRTIO_BALLOON_VQ_FREE_PAGE,

    /**
     * {@code VIRTIO_BALLOON_VQ_REPORTING = 4}
     */
    @EnumMember(
        value = 4L,
        name = "VIRTIO_BALLOON_VQ_REPORTING"
    )
    VIRTIO_BALLOON_VQ_REPORTING,

    /**
     * {@code VIRTIO_BALLOON_VQ_MAX = 5}
     */
    @EnumMember(
        value = 5L,
        name = "VIRTIO_BALLOON_VQ_MAX"
    )
    VIRTIO_BALLOON_VQ_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum virtio_balloon_config_read"
  )
  public enum virtio_balloon_config_read implements Enum<virtio_balloon_config_read>, TypedEnum<virtio_balloon_config_read, java.lang. @Unsigned Integer> {
    /**
     * {@code VIRTIO_BALLOON_CONFIG_READ_CMD_ID = 0}
     */
    @EnumMember(
        value = 0L,
        name = "VIRTIO_BALLOON_CONFIG_READ_CMD_ID"
    )
    VIRTIO_BALLOON_CONFIG_READ_CMD_ID
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_balloon"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_balloon extends Struct {
    public Ptr<virtio_device> vdev;

    public Ptr<virtqueue> inflate_vq;

    public Ptr<virtqueue> deflate_vq;

    public Ptr<virtqueue> stats_vq;

    public Ptr<virtqueue> free_page_vq;

    public Ptr<workqueue_struct> balloon_wq;

    public work_struct report_free_page_work;

    public work_struct update_balloon_stats_work;

    public work_struct update_balloon_size_work;

    public @OriginalName("spinlock_t") spinlock stop_update_lock;

    public boolean stop_update;

    public @Unsigned long config_read_bitmap;

    public list_head free_page_list;

    public @OriginalName("spinlock_t") spinlock free_page_list_lock;

    public @Unsigned long num_free_page_blocks;

    public @Unsigned int cmd_id_received_cache;

    public @Unsigned @OriginalName("__virtio32") int cmd_id_active;

    public @Unsigned @OriginalName("__virtio32") int cmd_id_stop;

    public @OriginalName("wait_queue_head_t") wait_queue_head acked;

    public @Unsigned int num_pages;

    public balloon_dev_info vb_dev_info;

    public mutex balloon_lock;

    public @Unsigned int num_pfns;

    public @Unsigned @OriginalName("__virtio32") int @Size(256) [] pfns;

    public virtio_balloon_stat @Size(16) [] stats;

    public Ptr<shrinker> shrinker;

    public notifier_block oom_nb;

    public Ptr<virtqueue> reporting_vq;

    public page_reporting_dev_info pr_dev_info;

    public @OriginalName("spinlock_t") spinlock wakeup_lock;

    public boolean processing_wakeup_event;

    public @Unsigned int wakeup_signal_mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_console_config"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_console_config extends Struct {
    public @Unsigned @OriginalName("__virtio16") short cols;

    public @Unsigned @OriginalName("__virtio16") short rows;

    public @Unsigned @OriginalName("__virtio32") int max_nr_ports;

    public @Unsigned @OriginalName("__virtio32") int emerg_wr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_console_control"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_console_control extends Struct {
    public @Unsigned @OriginalName("__virtio32") int id;

    public @Unsigned @OriginalName("__virtio16") short event;

    public @Unsigned @OriginalName("__virtio16") short value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_iommu_range_64"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_iommu_range_64 extends Struct {
    public @Unsigned @OriginalName("__le64") long start;

    public @Unsigned @OriginalName("__le64") long end;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_iommu_range_32"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_iommu_range_32 extends Struct {
    public @Unsigned @OriginalName("__le32") int start;

    public @Unsigned @OriginalName("__le32") int end;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_iommu_config"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_iommu_config extends Struct {
    public @Unsigned @OriginalName("__le64") long page_size_mask;

    public virtio_iommu_range_64 input_range;

    public virtio_iommu_range_32 domain_range;

    public @Unsigned @OriginalName("__le32") int probe_size;

    public char bypass;

    public char @Size(3) [] reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_iommu_req_head"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_iommu_req_head extends Struct {
    public char type;

    public char @Size(3) [] reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_iommu_req_tail"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_iommu_req_tail extends Struct {
    public char status;

    public char @Size(3) [] reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_iommu_req_attach"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_iommu_req_attach extends Struct {
    public virtio_iommu_req_head head;

    public @Unsigned @OriginalName("__le32") int domain;

    public @Unsigned @OriginalName("__le32") int endpoint;

    public @Unsigned @OriginalName("__le32") int flags;

    public char @Size(4) [] reserved;

    public virtio_iommu_req_tail tail;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_iommu_req_detach"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_iommu_req_detach extends Struct {
    public virtio_iommu_req_head head;

    public @Unsigned @OriginalName("__le32") int domain;

    public @Unsigned @OriginalName("__le32") int endpoint;

    public char @Size(8) [] reserved;

    public virtio_iommu_req_tail tail;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_iommu_req_map"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_iommu_req_map extends Struct {
    public virtio_iommu_req_head head;

    public @Unsigned @OriginalName("__le32") int domain;

    public @Unsigned @OriginalName("__le64") long virt_start;

    public @Unsigned @OriginalName("__le64") long virt_end;

    public @Unsigned @OriginalName("__le64") long phys_start;

    public @Unsigned @OriginalName("__le32") int flags;

    public virtio_iommu_req_tail tail;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_iommu_req_unmap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_iommu_req_unmap extends Struct {
    public virtio_iommu_req_head head;

    public @Unsigned @OriginalName("__le32") int domain;

    public @Unsigned @OriginalName("__le64") long virt_start;

    public @Unsigned @OriginalName("__le64") long virt_end;

    public char @Size(4) [] reserved;

    public virtio_iommu_req_tail tail;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_iommu_probe_property"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_iommu_probe_property extends Struct {
    public @Unsigned @OriginalName("__le16") short type;

    public @Unsigned @OriginalName("__le16") short length;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_iommu_probe_resv_mem"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_iommu_probe_resv_mem extends Struct {
    public virtio_iommu_probe_property head;

    public char subtype;

    public char @Size(3) [] reserved;

    public @Unsigned @OriginalName("__le64") long start;

    public @Unsigned @OriginalName("__le64") long end;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_iommu_req_probe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_iommu_req_probe extends Struct {
    public virtio_iommu_req_head head;

    public @Unsigned @OriginalName("__le32") int endpoint;

    public char @Size(64) [] reserved;

    public char @Size(0) [] properties;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_iommu_fault"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_iommu_fault extends Struct {
    public char reason;

    public char @Size(3) [] reserved;

    public @Unsigned @OriginalName("__le32") int flags;

    public @Unsigned @OriginalName("__le32") int endpoint;

    public char @Size(4) [] reserved2;

    public @Unsigned @OriginalName("__le64") long address;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_blk_geometry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_blk_geometry extends Struct {
    public @Unsigned @OriginalName("__virtio16") short cylinders;

    public char heads;

    public char sectors;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_blk_zoned_characteristics"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_blk_zoned_characteristics extends Struct {
    public @Unsigned @OriginalName("__virtio32") int zone_sectors;

    public @Unsigned @OriginalName("__virtio32") int max_open_zones;

    public @Unsigned @OriginalName("__virtio32") int max_active_zones;

    public @Unsigned @OriginalName("__virtio32") int max_append_sectors;

    public @Unsigned @OriginalName("__virtio32") int write_granularity;

    public char model;

    public char @Size(3) [] unused2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_blk_config"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_blk_config extends Struct {
    public @Unsigned @OriginalName("__virtio64") long capacity;

    public @Unsigned @OriginalName("__virtio32") int size_max;

    public @Unsigned @OriginalName("__virtio32") int seg_max;

    public virtio_blk_geometry geometry;

    public @Unsigned @OriginalName("__virtio32") int blk_size;

    public char physical_block_exp;

    public char alignment_offset;

    public @Unsigned @OriginalName("__virtio16") short min_io_size;

    public @Unsigned @OriginalName("__virtio32") int opt_io_size;

    public char wce;

    public char unused;

    public @Unsigned @OriginalName("__virtio16") short num_queues;

    public @Unsigned @OriginalName("__virtio32") int max_discard_sectors;

    public @Unsigned @OriginalName("__virtio32") int max_discard_seg;

    public @Unsigned @OriginalName("__virtio32") int discard_sector_alignment;

    public @Unsigned @OriginalName("__virtio32") int max_write_zeroes_sectors;

    public @Unsigned @OriginalName("__virtio32") int max_write_zeroes_seg;

    public char write_zeroes_may_unmap;

    public char @Size(3) [] unused1;

    public @Unsigned @OriginalName("__virtio32") int max_secure_erase_sectors;

    public @Unsigned @OriginalName("__virtio32") int max_secure_erase_seg;

    public @Unsigned @OriginalName("__virtio32") int secure_erase_sector_alignment;

    public virtio_blk_zoned_characteristics zoned;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_blk_outhdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_blk_outhdr extends Struct {
    public @Unsigned @OriginalName("__virtio32") int type;

    public @Unsigned @OriginalName("__virtio32") int ioprio;

    public @Unsigned @OriginalName("__virtio64") long sector;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_blk_zone_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_blk_zone_descriptor extends Struct {
    public @Unsigned @OriginalName("__virtio64") long z_cap;

    public @Unsigned @OriginalName("__virtio64") long z_start;

    public @Unsigned @OriginalName("__virtio64") long z_wp;

    public char z_type;

    public char z_state;

    public char @Size(38) [] reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_blk_zone_report"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_blk_zone_report extends Struct {
    public @Unsigned @OriginalName("__virtio64") long nr_zones;

    public char @Size(56) [] reserved;

    public virtio_blk_zone_descriptor @Size(0) [] zones;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_blk_discard_write_zeroes"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_blk_discard_write_zeroes extends Struct {
    public @Unsigned @OriginalName("__le64") long sector;

    public @Unsigned @OriginalName("__le32") int num_sectors;

    public @Unsigned @OriginalName("__le32") int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_blk_vq"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_blk_vq extends Struct {
    public Ptr<virtqueue> vq;

    public @OriginalName("spinlock_t") spinlock lock;

    public char @Size(16) [] name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_blk"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_blk extends Struct {
    public mutex vdev_mutex;

    public Ptr<virtio_device> vdev;

    public Ptr<gendisk> disk;

    public blk_mq_tag_set tag_set;

    public work_struct config_work;

    public int index;

    public int num_vqs;

    public int @Size(3) [] io_queues;

    public Ptr<virtio_blk_vq> vqs;

    public @Unsigned int zone_sectors;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_scsi_cmd_req"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_scsi_cmd_req extends Struct {
    public char @Size(8) [] lun;

    public @Unsigned @OriginalName("__virtio64") long tag;

    public char task_attr;

    public char prio;

    public char crn;

    public char @Size(32) [] cdb;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_scsi_cmd_req_pi"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_scsi_cmd_req_pi extends Struct {
    public char @Size(8) [] lun;

    public @Unsigned @OriginalName("__virtio64") long tag;

    public char task_attr;

    public char prio;

    public char crn;

    public @Unsigned @OriginalName("__virtio32") int pi_bytesout;

    public @Unsigned @OriginalName("__virtio32") int pi_bytesin;

    public char @Size(32) [] cdb;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_scsi_cmd_resp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_scsi_cmd_resp extends Struct {
    public @Unsigned @OriginalName("__virtio32") int sense_len;

    public @Unsigned @OriginalName("__virtio32") int resid;

    public @Unsigned @OriginalName("__virtio16") short status_qualifier;

    public char status;

    public char response;

    public char @Size(96) [] sense;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_scsi_ctrl_tmf_req"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_scsi_ctrl_tmf_req extends Struct {
    public @Unsigned @OriginalName("__virtio32") int type;

    public @Unsigned @OriginalName("__virtio32") int subtype;

    public char @Size(8) [] lun;

    public @Unsigned @OriginalName("__virtio64") long tag;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_scsi_ctrl_tmf_resp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_scsi_ctrl_tmf_resp extends Struct {
    public char response;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_scsi_ctrl_an_req"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_scsi_ctrl_an_req extends Struct {
    public @Unsigned @OriginalName("__virtio32") int type;

    public char @Size(8) [] lun;

    public @Unsigned @OriginalName("__virtio32") int event_requested;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_scsi_ctrl_an_resp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_scsi_ctrl_an_resp extends Struct {
    public @Unsigned @OriginalName("__virtio32") int event_actual;

    public char response;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_scsi_event"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_scsi_event extends Struct {
    public @Unsigned @OriginalName("__virtio32") int event;

    public char @Size(8) [] lun;

    public @Unsigned @OriginalName("__virtio32") int reason;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_scsi_config"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_scsi_config extends Struct {
    public @Unsigned @OriginalName("__virtio32") int num_queues;

    public @Unsigned @OriginalName("__virtio32") int seg_max;

    public @Unsigned @OriginalName("__virtio32") int max_sectors;

    public @Unsigned @OriginalName("__virtio32") int cmd_per_lun;

    public @Unsigned @OriginalName("__virtio32") int event_info_size;

    public @Unsigned @OriginalName("__virtio32") int sense_size;

    public @Unsigned @OriginalName("__virtio32") int cdb_size;

    public @Unsigned @OriginalName("__virtio16") short max_channel;

    public @Unsigned @OriginalName("__virtio16") short max_target;

    public @Unsigned @OriginalName("__virtio32") int max_lun;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_scsi_cmd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_scsi_cmd extends Struct {
    public Ptr<scsi_cmnd> sc;

    public Ptr<completion> comp;

    public req_of_virtio_scsi_cmd req;

    public resp_of_virtio_scsi_cmd resp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_scsi_event_node"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_scsi_event_node extends Struct {
    public Ptr<virtio_scsi> vscsi;

    public virtio_scsi_event event;

    public work_struct work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_scsi"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_scsi extends Struct {
    public Ptr<virtio_device> vdev;

    public virtio_scsi_event_node @Size(8) [] event_list;

    public @Unsigned int num_queues;

    public int @Size(3) [] io_queues;

    public hlist_node node;

    public boolean stop_events;

    public virtio_scsi_vq ctrl_vq;

    public virtio_scsi_vq event_vq;

    public virtio_scsi_vq @Size(0) [] req_vqs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_scsi_vq"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_scsi_vq extends Struct {
    public @OriginalName("spinlock_t") spinlock vq_lock;

    public Ptr<virtqueue> vq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_net_hdr_v1"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_net_hdr_v1 extends Struct {
    public char flags;

    public char gso_type;

    public @Unsigned @OriginalName("__virtio16") short hdr_len;

    public @Unsigned @OriginalName("__virtio16") short gso_size;

    @InlineUnion(50635)
    public anon_member_of_anon_member_of_virtio_net_hdr_v1 anon4$0;

    @InlineUnion(50635)
    public csum_of_anon_member_of_virtio_net_hdr_v1 csum;

    @InlineUnion(50635)
    public rsc_of_anon_member_of_virtio_net_hdr_v1 rsc;

    public @Unsigned @OriginalName("__virtio16") short num_buffers;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_net_hdr_v1_hash"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_net_hdr_v1_hash extends Struct {
    public virtio_net_hdr_v1 hdr;

    public @Unsigned @OriginalName("__le16") short hash_value_lo;

    public @Unsigned @OriginalName("__le16") short hash_value_hi;

    public @Unsigned @OriginalName("__le16") short hash_report;

    public @Unsigned @OriginalName("__le16") short padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_net_hdr_v1_hash_tunnel"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_net_hdr_v1_hash_tunnel extends Struct {
    public virtio_net_hdr_v1_hash hash_hdr;

    public @Unsigned @OriginalName("__le16") short outer_th_offset;

    public @Unsigned @OriginalName("__le16") short inner_nh_offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_net_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_net_hdr extends Struct {
    public char flags;

    public char gso_type;

    public @Unsigned @OriginalName("__virtio16") short hdr_len;

    public @Unsigned @OriginalName("__virtio16") short gso_size;

    public @Unsigned @OriginalName("__virtio16") short csum_start;

    public @Unsigned @OriginalName("__virtio16") short csum_offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_net_config"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_net_config extends Struct {
    public char @Size(6) [] mac;

    public @Unsigned @OriginalName("__virtio16") short status;

    public @Unsigned @OriginalName("__virtio16") short max_virtqueue_pairs;

    public @Unsigned @OriginalName("__virtio16") short mtu;

    public @Unsigned @OriginalName("__le32") int speed;

    public char duplex;

    public char rss_max_key_size;

    public @Unsigned @OriginalName("__le16") short rss_max_indirection_table_length;

    public @Unsigned @OriginalName("__le32") int supported_hash_types;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_net_hdr_mrg_rxbuf"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_net_hdr_mrg_rxbuf extends Struct {
    public virtio_net_hdr hdr;

    public @Unsigned @OriginalName("__virtio16") short num_buffers;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_net_ctrl_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_net_ctrl_hdr extends Struct {
    public char _class;

    public char cmd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_net_ctrl_mac"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_net_ctrl_mac extends Struct {
    public @Unsigned @OriginalName("__virtio32") int entries;

    public char @Size(0) [] macs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_net_ctrl_mq"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_net_ctrl_mq extends Struct {
    public @Unsigned @OriginalName("__virtio16") short virtqueue_pairs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_net_rss_config_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_net_rss_config_hdr extends Struct {
    public @Unsigned @OriginalName("__le32") int hash_types;

    public @Unsigned @OriginalName("__le16") short indirection_table_mask;

    public @Unsigned @OriginalName("__le16") short unclassified_queue;

    public @Unsigned @OriginalName("__le16") short @Size(0) [] indirection_table;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_net_rss_config_trailer"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_net_rss_config_trailer extends Struct {
    public @Unsigned @OriginalName("__le16") short max_tx_vq;

    public char hash_key_length;

    public char @Size(0) [] hash_key_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_net_ctrl_coal_tx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_net_ctrl_coal_tx extends Struct {
    public @Unsigned @OriginalName("__le32") int tx_max_packets;

    public @Unsigned @OriginalName("__le32") int tx_usecs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_net_ctrl_coal_rx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_net_ctrl_coal_rx extends Struct {
    public @Unsigned @OriginalName("__le32") int rx_max_packets;

    public @Unsigned @OriginalName("__le32") int rx_usecs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_net_ctrl_coal"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_net_ctrl_coal extends Struct {
    public @Unsigned @OriginalName("__le32") int max_packets;

    public @Unsigned @OriginalName("__le32") int max_usecs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_net_ctrl_coal_vq"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_net_ctrl_coal_vq extends Struct {
    public @Unsigned @OriginalName("__le16") short vqn;

    public @Unsigned @OriginalName("__le16") short reserved;

    public virtio_net_ctrl_coal coal;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_net_stats_capabilities"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_net_stats_capabilities extends Struct {
    public @Unsigned @OriginalName("__le64") long @Size(1) [] supported_stats_types;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_net_ctrl_queue_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_net_ctrl_queue_stats extends Struct {
    public AnonymousType1872417052C117 @Size(1) [] stats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_net_stats_reply_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_net_stats_reply_hdr extends Struct {
    public char type;

    public char reserved;

    public @Unsigned @OriginalName("__le16") short vq_index;

    public @Unsigned @OriginalName("__le16") short reserved1;

    public @Unsigned @OriginalName("__le16") short size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct virtio_net_common_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class virtio_net_common_hdr extends Struct {
    @InlineUnion(50822)
    public virtio_net_hdr hdr;

    @InlineUnion(50822)
    public virtio_net_hdr_mrg_rxbuf mrg_hdr;

    @InlineUnion(50822)
    public virtio_net_hdr_v1_hash hash_v1_hdr;

    @InlineUnion(50822)
    public virtio_net_hdr_v1_hash_tunnel tnl_hdr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int vq_index; short unsigned int reserved[3]; long long unsigned int types_bitmap[1]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class AnonymousType1872417052C117 extends Struct {
    public @Unsigned @OriginalName("__le16") short vq_index;

    public @Unsigned @OriginalName("__le16") short @Size(3) [] reserved;

    public @Unsigned @OriginalName("__le64") long @Size(1) [] types_bitmap;
  }
}
